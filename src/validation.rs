use std::{cell::Cell, fmt, fs, io, sync::Arc};

use camino::Utf8PathBuf;
use der::Decode as _;
use eyre::{WrapErr as _, eyre};
use rustls::server::ParsedCertificate;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Value, json};
use x509_cert::Certificate;

#[derive(Debug)]
pub(crate) struct Verifier {
    pub(crate) provider: Arc<rustls::crypto::CryptoProvider>,
    roots: rustls::RootCertStore,
}

#[derive(Clone, Debug)]
pub(crate) struct CustomRoots {
    store: rustls::RootCertStore,
}

pub(crate) fn read_ca_files(ca_files: &[Utf8PathBuf]) -> eyre::Result<CustomRoots> {
    let mut roots = Vec::new();

    for path in ca_files {
        let file =
            fs::File::open(path).wrap_err_with(|| format!("Could not open CA file: {path}"))?;
        let certs = rustls_pemfile::certs(&mut io::BufReader::new(file))
            .collect::<Result<Vec<_>, _>>()
            .wrap_err_with(|| format!("Could not read CA certificates from: {path}"))?;

        if certs.is_empty() {
            return Err(eyre!("CA file contained 0 certificates: {path}"));
        }

        for cert in &certs {
            Certificate::from_der(cert)
                .wrap_err_with(|| format!("Invalid CA certificate in: {path}"))?;
        }

        roots.extend(certs);
    }

    let mut root_store = rustls::RootCertStore::empty();

    for root in &roots {
        root_store
            .add(root.clone())
            .wrap_err("Invalid custom trust root")?;
    }

    Ok(CustomRoots { store: root_store })
}

pub(crate) fn verifier(ca_files: &[Utf8PathBuf]) -> eyre::Result<Verifier> {
    Ok(Verifier::new(read_ca_files(ca_files)?))
}

impl Verifier {
    pub(crate) fn new(mut custom: CustomRoots) -> Self {
        let native = rustls_native_certs::load_native_certs();
        let (_, ignored) = custom
            .store
            .add_parsable_certificates(native.certs.iter().cloned());

        if ignored > 0 {
            tracing::warn!("Ignored {ignored} invalid system trust roots");
        }

        for error in native.errors {
            tracing::warn!("Could not load a system trust root: {error}");
        }

        Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            roots: custom.store,
        }
    }

    fn verify_path(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        revocation: Option<webpki::RevocationOptions<'_>>,
    ) -> Result<(), PathError> {
        let invalid_key_usage = Cell::new(false);

        // WebPKI does not check CA key usage. Check each candidate path so
        // an unused intermediate cannot invalidate a valid alternative.
        let check_key_usage = |path: &webpki::VerifiedPath<'_>| {
            for intermediate in path.intermediate_certificates() {
                let cert = Certificate::from_der(intermediate.der().as_ref())
                    .map_err(|_| webpki::Error::BadDer)?;
                let usage = cert
                    .tbs_certificate()
                    .get_extension::<x509_cert::ext::pkix::KeyUsage>()
                    .map_err(|_| webpki::Error::ExtensionValueInvalid)?;

                if usage.is_some_and(|(_, usage)| !usage.key_cert_sign()) {
                    invalid_key_usage.set(true);
                    return Err(webpki::Error::ExtensionValueInvalid);
                }
            }

            Ok(())
        };

        let verify_path = || {
            let cert = webpki::EndEntityCert::try_from(end_entity)?;

            cert.verify_for_usage(
                self.provider.signature_verification_algorithms.all,
                &self.roots.roots,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                revocation,
                Some(&check_key_usage),
            )?;

            Ok::<_, webpki::Error>(())
        };

        verify_path().map_err(|err| {
            if err == webpki::Error::ExtensionValueInvalid && invalid_key_usage.get() {
                PathError::CaKeyUsage
            } else {
                PathError::Certificate(err)
            }
        })
    }
}

#[derive(Clone, Debug)]
enum PathError {
    Certificate(webpki::Error),
    CaKeyUsage,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaKeyUsage => f.write_str("CA does not allow certificate signing"),
            Self::Certificate(err) => f.write_str(&certificate_error(err)),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Report {
    path: Result<(), PathError>,
    hostname: Result<(), rustls::Error>,
    server_name: String,
    now: UnixTime,
    pub(crate) revocation: Option<RevocationStatus>,
    pub(crate) handshake_signature: Option<Result<(), rustls::Error>>,
}

impl Report {
    pub(crate) fn check(
        verifier: &Verifier,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Self {
        Self {
            path: verifier.verify_path(end_entity, intermediates, now, None),
            hostname: ParsedCertificate::try_from(end_entity)
                .and_then(|cert| rustls::client::verify_server_name(&cert, server_name)),
            server_name: server_name.to_str().into_owned(),
            now,
            revocation: None,
            handshake_signature: None,
        }
    }

    fn has_failure(&self) -> bool {
        self.path.is_err()
            || self.hostname.is_err()
            || self
                .handshake_signature
                .as_ref()
                .is_some_and(Result::is_err)
            || matches!(self.revocation, Some(RevocationStatus::Revoked))
    }

    pub(crate) fn can_check_revocation(&self) -> bool {
        self.path.is_ok()
    }

    pub(crate) fn check_revocation(
        &mut self,
        verifier: &Verifier,
        certs: &[CertificateDer<'_>],
        crls: &[Vec<u8>],
    ) {
        self.revocation = Some(self.revocation_status(verifier, certs, crls));
    }

    fn revocation_status(
        &self,
        verifier: &Verifier,
        certs: &[CertificateDer<'_>],
        crls: &[Vec<u8>],
    ) -> RevocationStatus {
        if !self.can_check_revocation() {
            return RevocationStatus::Unknown("certificate path is invalid".to_owned());
        }

        let mut parsed = Vec::new();
        let mut reason = "no authoritative CRL for the certificate".to_owned();

        for crl in crls {
            let Ok(list) =
                x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(crl)
            else {
                reason = "invalid CRL encoding".to_owned();
                continue;
            };
            let this_update = list.tbs_cert_list.this_update.to_unix_duration().as_secs();

            // WebPKI checks nextUpdate, but does not check thisUpdate.
            if this_update > self.now.as_secs() {
                reason = "CRL is not yet valid".to_owned();
                continue;
            }

            match webpki::BorrowedCertRevocationList::from_der(crl) {
                Ok(crl) => parsed.push((this_update, webpki::CertRevocationList::Borrowed(crl))),
                Err(error) => reason = certificate_error(&error),
            }
        }

        // Prefer the newest authoritative CRL when several files cover a leaf.
        parsed.sort_by_key(|(time, _)| std::cmp::Reverse(*time));

        for (_, crl) in &parsed {
            let crls = [crl];
            let options = webpki::RevocationOptionsBuilder::new(&crls)
                .expect("one CRL was supplied")
                .with_depth(webpki::RevocationCheckDepth::EndEntity)
                .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
                .build();

            match verifier.verify_path(&certs[0], &certs[1..], self.now, Some(options)) {
                Ok(()) => return RevocationStatus::Valid,
                Err(PathError::Certificate(webpki::Error::CertRevoked)) => {
                    return RevocationStatus::Revoked;
                }
                Err(error) => reason = error.to_string(),
            }
        }

        RevocationStatus::Unknown(reason)
    }

    fn status(&self) -> &'static str {
        if self.has_failure() {
            "invalid"
        } else if matches!(self.revocation, Some(RevocationStatus::Unknown(_))) {
            "unknown"
        } else {
            "valid"
        }
    }

    fn path_result(&self, certs: &[Certificate]) -> Result<(), String> {
        self.path.as_ref().copied().map_err(|error| match error {
            PathError::Certificate(webpki::Error::UnknownIssuer) => issuer_error(certs).to_owned(),
            error => error.to_string(),
        })
    }

    fn date_result(&self, cert: &Certificate) -> Result<(), &'static str> {
        let validity = cert.tbs_certificate().validity();
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();
        let now = self.now.as_secs();

        if not_before > not_after {
            Err("invalid validity period")
        } else if now < not_before {
            Err("not yet valid")
        } else if now > not_after {
            Err("expired")
        } else {
            Ok(())
        }
    }

    pub(crate) fn to_json(&self, certs: &[Certificate]) -> Value {
        let mut hostname = json_status(&self.hostname.as_ref().map_err(tls_error));

        hostname["name"] = json!(self.server_name);

        let revocation = match &self.revocation {
            Some(RevocationStatus::Valid) => json!({ "status": "valid" }),
            Some(RevocationStatus::Revoked) => {
                json!({ "status": "invalid", "reason": "certificate revoked" })
            }
            Some(RevocationStatus::Unknown(reason)) => {
                json!({ "status": "unknown", "reason": reason })
            }
            None => json!({ "status": "not_checked" }),
        };
        let mut value = json!({
            "status": self.status(),
            "path": json_status(&self.path_result(certs)),
            "hostname": hostname,
            "dates": certs.iter().map(|cert| json_status(&self.date_result(cert))).collect::<Vec<_>>(),
            "revocation": revocation,
        });

        if let Some(result) = &self.handshake_signature {
            value["handshake_signature"] = json_status(&result.as_ref().map_err(tls_error));
        }

        value
    }

    pub(crate) fn write_to(
        &self,
        certs: &[Certificate],
        mut out: impl io::Write,
    ) -> io::Result<()> {
        writeln!(
            out,
            "Certificate chain: {}",
            self.status().to_ascii_uppercase(),
        )?;

        write!(out, "Path validation: ")?;
        write_status(&mut out, &self.path_result(certs))?;

        write!(out, "Hostname ({}): ", self.server_name)?;
        write_status(&mut out, &self.hostname.as_ref().map_err(tls_error))?;

        for (index, cert) in certs.iter().enumerate() {
            write!(out, "Certificate {} dates: ", index + 1)?;
            write_status(&mut out, &self.date_result(cert))?;
        }

        if let Some(result) = &self.handshake_signature {
            write!(out, "TLS handshake signature: ")?;
            write_status(&mut out, &result.as_ref().map_err(tls_error))?;
        }

        if let Some(status) = &self.revocation {
            write!(out, "Revocation (leaf): ")?;

            match status {
                RevocationStatus::Valid => writeln!(out, "VALID")?,
                RevocationStatus::Revoked => writeln!(out, "INVALID (certificate revoked)")?,
                RevocationStatus::Unknown(reason) => writeln!(out, "UNKNOWN ({reason})")?,
            }
        } else {
            writeln!(out, "Revocation (leaf): NOT CHECKED")?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) enum RevocationStatus {
    Valid,
    Revoked,
    Unknown(String),
}

fn json_status<T, E: fmt::Display>(result: &Result<T, E>) -> Value {
    match result {
        Ok(_) => json!({ "status": "valid" }),
        Err(error) => json!({ "status": "invalid", "reason": error.to_string() }),
    }
}

fn write_status<T, E: fmt::Display>(
    out: &mut impl io::Write,
    result: &Result<T, E>,
) -> io::Result<()> {
    match result {
        Ok(_) => writeln!(out, "VALID"),
        Err(err) => writeln!(out, "INVALID ({err})"),
    }
}

fn issuer_error(certs: &[Certificate]) -> &'static str {
    let Some(mut cert) = certs.first() else {
        return "issuer is not trusted";
    };

    for index in 0..certs.len() {
        let tbs = cert.tbs_certificate();

        if tbs.subject() == tbs.issuer() {
            return if index == 0 {
                "self-issued certificate is not trusted"
            } else {
                "root CA is not trusted"
            };
        }

        let Some(issuer) = certs
            .iter()
            .find(|issuer| issuer.tbs_certificate().subject() == tbs.issuer())
        else {
            break;
        };

        cert = issuer;
    }

    "missing issuer certificate or untrusted issuer"
}

fn certificate_error(error: &webpki::Error) -> String {
    use webpki::Error as E;

    let message = match error {
        E::CertExpired { .. } => "certificate expired",
        E::CertNotValidYet { .. } => "certificate is not yet valid",
        E::CertRevoked => "certificate revoked",
        E::InvalidSignatureForPublicKey => "invalid certificate signature",
        E::InvalidCrlSignatureForPublicKey => "invalid CRL signature",
        E::CrlExpired { .. } => "CRL expired",
        E::UnknownRevocationStatus => "no authoritative CRL for the certificate",
        E::IssuerNotCrlSigner => "issuer does not allow CRL signing",
        E::UnknownIssuer => "issuer is not trusted",
        E::EndEntityUsedAsCa => "issuer is not a CA",
        E::CaUsedAsEndEntity => "CA certificate used as a server certificate",
        E::PathLenConstraintViolated => "CA path length constraint violated",
        E::NameConstraintViolation => "CA name constraint violated",
        E::RequiredEkuNotFoundContext(_) | E::EmptyEkuExtension => {
            "certificate does not allow TLS server authentication"
        }
        E::UnsupportedCriticalExtension => "unsupported critical extension",
        E::SignatureAlgorithmMismatch => "certificate signature algorithms do not match",
        E::UnsupportedSignatureAlgorithmContext(_)
        | E::UnsupportedSignatureAlgorithmForPublicKeyContext(_) => {
            "unsupported certificate signature algorithm"
        }
        E::InvalidCertValidity => "invalid certificate validity period",
        E::BadDer | E::BadDerTime | E::MalformedExtensions | E::ExtensionValueInvalid => {
            "invalid certificate or CRL encoding"
        }
        _ => return error.to_string(),
    };

    message.to_owned()
}

fn tls_error(error: &rustls::Error) -> String {
    use rustls::CertificateError as E;

    match error {
        rustls::Error::InvalidCertificate(
            E::NotValidForName | E::NotValidForNameContext { .. },
        ) => "hostname does not match certificate names".to_owned(),
        rustls::Error::InvalidCertificate(E::BadSignature) => "invalid signature".to_owned(),
        _ => error.to_string(),
    }
}
