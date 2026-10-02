use std::{io, time::SystemTime};

use clap::ValueEnum;
use eyre::WrapErr as _;
use itertools::Itertools as _;
use serde_json::{Map, Value, json};
use x509_cert::{Certificate, ext::pkix::SubjectAltName};

use crate::{ext, util};

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum Field {
    Subject,
    Issuer,
    Version,
    SerialNumber,
    SignatureAlgorithm,
    NotBefore,
    NotAfter,
    ExpiresInSeconds,
    SubjectAltNames,
    PublicKey,
    Extensions,
    Signature,
}

impl Field {
    fn name(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Issuer => "issuer",
            Self::Version => "version",
            Self::SerialNumber => "serial_number",
            Self::SignatureAlgorithm => "signature_algorithm",
            Self::NotBefore => "not_before",
            Self::NotAfter => "not_after",
            Self::ExpiresInSeconds => "expires_in_seconds",
            Self::SubjectAltNames => "subject_alt_names",
            Self::PublicKey => "public_key",
            Self::Extensions => "extensions",
            Self::Signature => "signature",
        }
    }

    fn value(self, cert: &Certificate, now: SystemTime) -> eyre::Result<Value> {
        let tbs = cert.tbs_certificate();

        Ok(match self {
            Self::Subject => json!(tbs.subject().to_string()),
            Self::Issuer => json!(tbs.issuer().to_string()),
            Self::Version => json!(tbs.version() as u8 + 1),
            Self::SerialNumber => json!(hex(tbs.serial_number().as_bytes())),
            Self::SignatureAlgorithm => json!({
                "oid": cert.signature_algorithm().oid.to_string(),
                "name": util::oid_desc_or_raw(&cert.signature_algorithm().oid),
            }),
            Self::NotBefore => json!(tbs.validity().not_before.to_string()),
            Self::NotAfter => json!(tbs.validity().not_after.to_string()),
            Self::ExpiresInSeconds => {
                let expiry = tbs.validity().not_after.to_system_time();
                let seconds = match expiry.duration_since(now) {
                    Ok(remaining) => remaining.as_secs() as i64,
                    Err(elapsed) => {
                        let elapsed = elapsed.duration();

                        -(elapsed.as_secs() as i64) - i64::from(elapsed.subsec_nanos() > 0)
                    }
                };

                json!(seconds)
            }
            Self::SubjectAltNames => {
                let names = tbs
                    .get_extension::<SubjectAltName>()
                    .wrap_err("Failed to parse subject alternate names")?
                    .map(|(_, names)| {
                        names
                            .0
                            .iter()
                            .map(ext::fmt_general_name)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                json!(names)
            }
            Self::PublicKey => {
                let spki = tbs.subject_public_key_info();

                json!({
                    "algorithm": {
                        "oid": spki.algorithm.oid.to_string(),
                        "name": util::oid_desc_or_raw(&spki.algorithm.oid),
                    },
                    "value": hex(spki.subject_public_key.raw_bytes()),
                })
            }
            Self::Extensions => json!(
                tbs.extensions()
                    .into_iter()
                    .flatten()
                    .map(|extension| {
                        json!({
                            "oid": extension.extn_id.to_string(),
                            "name": util::oid_desc_or_raw(&extension.extn_id),
                            "critical": extension.critical,
                            "value": hex(extension.extn_value.as_bytes()),
                        })
                    })
                    .collect::<Vec<_>>()
            ),
            Self::Signature => json!(hex(cert.signature().raw_bytes())),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).join("")
}

pub(crate) struct Report<'a> {
    certs: &'a [Certificate],
    fields: &'a [Field],
    now: SystemTime,
}

impl<'a> Report<'a> {
    pub(crate) fn new(certs: &'a [Certificate], fields: &'a [Field]) -> Self {
        let now = SystemTime::now();

        Self { certs, fields, now }
    }

    pub(crate) fn write_json(&self, mut writer: impl io::Write) -> eyre::Result<()> {
        let fields = if self.fields.is_empty() {
            Field::value_variants()
        } else {
            self.fields
        };
        let certificates = self
            .certs
            .iter()
            .map(|cert| {
                fields
                    .iter()
                    .map(|&field| Ok((field.name().to_owned(), field.value(cert, self.now)?)))
                    .collect::<eyre::Result<Map<_, _>>>()
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let value = json!({ "certificates": certificates });

        serde_json::to_writer_pretty(&mut writer, &value)?;
        writeln!(writer)?;

        Ok(())
    }

    pub(crate) fn write_fields(&self, mut writer: impl io::Write) -> eyre::Result<()> {
        for cert in self.certs {
            writeln!(writer, "Certificate\n===========")?;

            for &field in self.fields {
                let value = field.value(cert, self.now)?;

                let value = match value {
                    Value::String(value) => value,
                    value => value.to_string(),
                };

                writeln!(writer, "{}: {value}", field.name())?;
            }

            writeln!(writer)?;
        }

        Ok(())
    }
}
