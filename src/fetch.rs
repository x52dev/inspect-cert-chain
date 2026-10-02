use std::{
    net::TcpStream,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use der::Decode;
use eyre::{WrapErr as _, eyre};
use rustls_pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt as _;
use x509_cert::Certificate;

pub(crate) fn cert_chain(
    host: &str,
    port: u16,
    server_name: &str,
    timeout: Duration,
) -> eyre::Result<Vec<Certificate>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| eyre!("Timeout is too large"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_host = host.to_owned();
    let worker_server_name = server_name.to_owned();

    // DNS and socket operations can block. Do not join the worker on timeout;
    // returning the error makes the CLI exit and stop the worker.
    thread::Builder::new().spawn(move || {
        let _ = sender.send(fetch_cert_chain(&worker_host, port, &worker_server_name));
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

fn fetch_cert_chain(host: &str, port: u16, server_name: &str) -> eyre::Result<Vec<Certificate>> {
    let tls_server_name = ServerName::try_from(server_name)
        .with_context(|| format!("Invalid TLS server name: \"{server_name}\""))?
        .to_owned();

    let mut config = rustls::ClientConfig::builder()
        .with_platform_verifier()?
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoopServerCertVerifier));

    let mut conn = rustls::ClientConnection::new(Arc::new(config), tls_server_name)?;
    let mut sock = TcpStream::connect((host, port))
        .wrap_err_with(|| format!("Failed to connect to host: {host}:{port}"))?;

    conn.complete_io(&mut sock)
        .wrap_err_with(|| format!("Failed to complete TLS handshake with {host}:{port}"))?;

    Ok(conn
        .peer_certificates()
        .map(|c| {
            c.iter()
                .filter_map(|c| Certificate::from_der(c).ok())
                .collect()
        })
        .unwrap_or_default())
}

#[derive(Debug)]
struct NoopServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
