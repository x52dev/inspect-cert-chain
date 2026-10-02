use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use der::Decode;
use error_reporter::Report;
use eyre::{WrapErr as _, eyre};
use rustls_pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt as _;
use x509_cert::Certificate;

pub(crate) fn cert_chain(
    host: &str,
    port: u16,
    timeout: Duration,
) -> eyre::Result<Vec<Certificate>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| eyre!("Timeout is too large"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_host = host.to_owned();

    // DNS and socket operations can block. Do not join the worker on timeout;
    // returning the error makes the CLI exit and stop the worker.
    thread::Builder::new().spawn(move || {
        let _ = sender.send(fetch_cert_chain(&worker_host, port));
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

fn fetch_cert_chain(host: &str, port: u16) -> eyre::Result<Vec<Certificate>> {
    let server_name = ServerName::try_from(host)
        .with_context(|| format!("Failed to convert given host (\"{host}\") to server name"))?
        .to_owned();

    let mut config = rustls::ClientConfig::builder()
        .with_platform_verifier()?
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoopServerCertVerifier));

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect(format!("{host}:{port}"))
        .wrap_err_with(|| format!("Failed to connect to host: {host}:{port}"))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let req = format!(
        r#"GET / HTTP/1.1
Host: {host}
Connection: close
User-Agent: inspect-cert-chain/{}
Accept-Encoding: identity

"#,
        env!("CARGO_PKG_VERSION"),
    )
    .replace('\n', "\r\n");

    tracing::debug!("writing to socket:\n{req}");

    tls.write_all(req.as_bytes())
        .wrap_err("Failed to write to socket")?;
    tls.flush().wrap_err("Failed to flush socket")?;

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(_) => {}
        Err(err) => {
            tracing::warn!("Failed to read from {host}: {}", Report::new(err));
        }
    }

    // peer_certificates method will return certificates by now
    // because app data has already been written
    tls.conn
        .peer_certificates()
        .map(parse_cert_chain)
        .unwrap_or_else(|| Err(eyre!("Chain contained 0 certificates")))
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
