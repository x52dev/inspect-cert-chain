use std::{
    net::TcpStream,
    sync::{Arc, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use der::Decode;
use eyre::{WrapErr as _, eyre};
use rustls_pki_types::ServerName;
use x509_cert::Certificate;

use crate::{revocation, validation};

pub(crate) struct FetchedChain {
    pub(crate) certs: Vec<Certificate>,
    pub(crate) validation: validation::Report,
}

pub(crate) fn cert_chain(
    host: &str,
    port: u16,
    server_name: &str,
    timeout: Duration,
    ca_files: Vec<camino::Utf8PathBuf>,
    crl_files: Vec<camino::Utf8PathBuf>,
) -> eyre::Result<FetchedChain> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| eyre!("Timeout is too large"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_host = host.to_owned();
    let worker_server_name = server_name.to_owned();

    // DNS and socket operations can block. Do not join the worker on timeout;
    // returning the error makes the CLI exit and stop the worker.
    thread::Builder::new().spawn(move || {
        let _ = sender.send(fetch_cert_chain(
            &worker_host,
            port,
            &worker_server_name,
            &ca_files,
            &crl_files,
            deadline,
        ));
    })?;

    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) if Instant::now() < deadline => result,
        Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => Err(eyre!(
            "Remote certificate fetch from {host}:{port} timed out after {}",
            humantime::format_duration(timeout),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(eyre!("Certificate fetch worker stopped without a result"))
        }
    }
}

fn fetch_cert_chain(
    host: &str,
    port: u16,
    server_name: &str,
    ca_files: &[camino::Utf8PathBuf],
    crl_files: &[camino::Utf8PathBuf],
    deadline: Instant,
) -> eyre::Result<FetchedChain> {
    let supplied_crls = revocation::read_files(crl_files)?;
    let tls_server_name = ServerName::try_from(server_name)
        .with_context(|| format!("Invalid TLS server name: \"{server_name}\""))?
        .to_owned();

    let verifier = Arc::new(ReportingServerCertVerifier {
        roots: validation::read_ca_files(ca_files)?,
        provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        inner: OnceLock::new(),
        report: OnceLock::new(),
        handshake_signature: OnceLock::new(),
    });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), tls_server_name)?;
    let mut sock = TcpStream::connect((host, port))
        .wrap_err_with(|| format!("Failed to connect to host: {host}:{port}"))?;

    conn.complete_io(&mut sock)
        .wrap_err_with(|| format!("Failed to complete TLS handshake with {host}:{port}"))?;

    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| eyre!("Server did not provide a certificate chain"))?;
    let certs = parse_cert_chain(peer_certs)?;

    let mut validation = verifier
        .report
        .get()
        .cloned()
        .ok_or_else(|| eyre!("Server certificate validation did not run"))?;

    validation.handshake_signature = Some(
        verifier
            .handshake_signature
            .get()
            .cloned()
            .ok_or_else(|| eyre!("TLS handshake signature validation did not run"))?,
    );

    if !crl_files.is_empty() {
        validation.check_revocation(verifier.inner(), peer_certs, &supplied_crls);
    } else if validation.can_check_revocation() {
        match revocation::download(&certs[0], verifier.inner(), deadline) {
            Ok(crls) => validation.check_revocation(verifier.inner(), peer_certs, &crls),
            Err(error) => {
                validation.revocation =
                    Some(validation::RevocationStatus::Unknown(format!("{error:#}")))
            }
        }
    } else {
        validation.revocation = Some(validation::RevocationStatus::Unknown(
            "certificate path is invalid".to_owned(),
        ));
    }

    Ok(FetchedChain { certs, validation })
}

fn parse_cert_chain(
    certs: &[rustls_pki_types::CertificateDer<'_>],
) -> eyre::Result<Vec<Certificate>> {
    certs
        .iter()
        .map(|cert| Certificate::from_der(cert))
        .collect::<Result<_, _>>()
        .wrap_err("Failed to parse remote certificate chain")
}

#[derive(Debug)]
struct ReportingServerCertVerifier {
    roots: validation::CustomRoots,
    provider: Arc<rustls::crypto::CryptoProvider>,
    inner: OnceLock<validation::Verifier>,
    report: OnceLock<validation::Report>,
    handshake_signature: OnceLock<Result<(), rustls::Error>>,
}

impl ReportingServerCertVerifier {
    fn inner(&self) -> &validation::Verifier {
        // Load system roots only when the server supplies certificates. A slow
        // trust store must not delay ClientHello or a stalled-handshake timeout.
        self.inner
            .get_or_init(|| validation::Verifier::new(self.roots.clone()))
    }
}

impl rustls::client::danger::ServerCertVerifier for ReportingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let _ = self.report.set(validation::Report::check(
            self.inner(),
            end_entity,
            intermediates,
            server_name,
            now,
        ));

        // Inspection must remain available when the certificate path is invalid.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let _ = self.handshake_signature.set(
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
            .map(|_| ()),
        );

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let _ = self.handshake_signature.set(
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
            .map(|_| ()),
        );

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_intermediate_is_an_error_instead_of_a_partial_chain() {
        let mut pem = include_bytes!("../tests/fixtures/server.pem").as_slice();
        let leaf = rustls_pemfile::certs(&mut pem).next().unwrap().unwrap();
        let invalid = rustls_pki_types::CertificateDer::from(vec![0x30, 0x00]);

        let error = parse_cert_chain(&[leaf, invalid]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "Failed to parse remote certificate chain"
        );
    }
}
