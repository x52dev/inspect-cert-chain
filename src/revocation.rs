use std::{
    fs,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use camino::Utf8PathBuf;
use der::Decode as _;
use eyre::{WrapErr as _, eyre};
use x509_cert::{
    Certificate,
    ext::pkix::{
        CrlDistributionPoints,
        name::{DistributionPointName, GeneralName},
    },
};

use crate::validation::Verifier;

pub(crate) fn read_files(paths: &[Utf8PathBuf]) -> eyre::Result<Vec<Vec<u8>>> {
    let mut crls = Vec::new();

    for path in paths {
        let bytes = fs::read(path).wrap_err_with(|| format!("Could not open CRL file: {path}"))?;

        crls.extend(decode_crls(&bytes).wrap_err_with(|| format!("Invalid CRL file: {path}"))?);
    }

    Ok(crls)
}

pub(crate) fn download(
    leaf: &Certificate,
    verifier: &Verifier,
    deadline: Instant,
) -> eyre::Result<Vec<Vec<u8>>> {
    let points = leaf
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()?
        .ok_or_else(|| eyre!("certificate has no CRL distribution points"))?
        .1;
    let urls = points
        .0
        .into_iter()
        .filter_map(|point| match point.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri)
                if uri.as_str().starts_with("http://") || uri.as_str().starts_with("https://") =>
            {
                Some(uri.to_string())
            }
            _ => None,
        })
        .take(8)
        .collect::<Vec<_>>();

    if urls.is_empty() {
        return Err(eyre!(
            "certificate has no supported HTTP CRL distribution points"
        ));
    }

    let roots = verifier
        .root_certificates
        .iter()
        .map(|der| ureq::tls::Certificate::from_der(der).to_owned());
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::from(roots))
        .unversioned_rustls_crypto_provider(verifier.provider.clone())
        .build();
    let agent: ureq::Agent = ureq::Agent::config_builder().tls_config(tls).build().into();

    // DNS and socket timeouts can overrun. Keep a separate deadline for CRL
    // retrieval so an unavailable service cannot discard the certificate report.
    let budget = deadline
        .saturating_duration_since(Instant::now())
        .saturating_sub(Duration::from_millis(100))
        .min(Duration::from_secs(5));

    if budget.is_zero() {
        return Err(eyre!("CRL download timed out"));
    }

    let crl_deadline = Instant::now() + budget;
    let (sender, receiver) = mpsc::sync_channel(1);

    thread::Builder::new().spawn(move || {
        let _ = sender.send(download_urls(agent, urls, crl_deadline));
    })?;

    match receiver.recv_timeout(crl_deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(eyre!("CRL download timed out")),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(eyre!("CRL download worker stopped without a result"))
        }
    }
}

fn download_urls(
    agent: ureq::Agent,
    urls: Vec<String>,
    crl_deadline: Instant,
) -> eyre::Result<Vec<Vec<u8>>> {
    let mut crls = Vec::new();
    let mut last_error = eyre!("CRL download timed out");

    for url in urls {
        let remaining = crl_deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            break;
        }

        let result = (|| {
            let bytes = agent
                .get(&url)
                .config()
                .timeout_global(Some(remaining))
                .build()
                .call()?
                .body_mut()
                .with_config()
                .limit(10 * 1024 * 1024)
                .read_to_vec()?;

            decode_crls(&bytes)
        })();

        match result {
            Ok(lists) => crls.extend(lists),
            Err(error) => last_error = error,
        }
    }

    if crls.is_empty() {
        return Err(last_error.wrap_err("could not download a usable CRL"));
    }

    Ok(crls)
}

fn decode_crls(bytes: &[u8]) -> eyre::Result<Vec<Vec<u8>>> {
    let crls = if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'-')
    {
        rustls_pemfile::crls(&mut &*bytes)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|crl| crl.to_vec())
            .collect::<Vec<_>>()
    } else {
        vec![bytes.to_vec()]
    };

    if crls.is_empty() {
        return Err(eyre!("CRL file contained 0 revocation lists"));
    }

    for crl in &crls {
        x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl)
            .wrap_err("invalid CRL encoding")?;
    }

    Ok(crls)
}
