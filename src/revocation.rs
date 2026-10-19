use std::fs;

use camino::Utf8PathBuf;
use der::Decode as _;
use eyre::{WrapErr as _, eyre};

pub(crate) fn read_files(paths: &[Utf8PathBuf]) -> eyre::Result<Vec<Vec<u8>>> {
    let mut crls = Vec::new();

    for path in paths {
        let bytes = fs::read(path).wrap_err_with(|| format!("Could not open CRL file: {path}"))?;

        crls.extend(decode_crls(&bytes).wrap_err_with(|| format!("Invalid CRL file: {path}"))?);
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
