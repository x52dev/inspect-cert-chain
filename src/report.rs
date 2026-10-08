use std::{
    io,
    time::{Duration, SystemTime},
};

use clap::ValueEnum;
use eyre::WrapErr as _;
use itertools::Itertools as _;
use serde_json::{Map, Value, json};
use x509_cert::{Certificate, ext::pkix::SubjectAltName, time::Validity};

use crate::{ext, util, validation};

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
    Status,
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
            Self::Status => "status",
        }
    }

    fn value(
        self,
        cert: &Certificate,
        assessment: Assessment,
        now: SystemTime,
    ) -> eyre::Result<Value> {
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
            Self::Status => json!({
                "level": assessment.status.as_str(),
                "reason": assessment.reason,
            }),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).join("")
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum Status {
    Ok = 0,
    Warning = 1,
    Critical = 2,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Assessment {
    status: Status,
    reason: &'static str,
}

fn assess(
    validity: &Validity,
    now: SystemTime,
    warn_within: Option<Duration>,
    critical_within: Option<Duration>,
) -> Assessment {
    let not_before = validity.not_before.to_system_time();
    let not_after = validity.not_after.to_system_time();

    let (status, reason) = if not_before > not_after {
        (Status::Critical, "invalid validity period")
    } else if now < not_before {
        (Status::Critical, "not yet valid")
    } else if now > not_after {
        (Status::Critical, "expired")
    } else {
        let remaining = not_after.duration_since(now).unwrap_or_default();

        if critical_within.is_some_and(|threshold| remaining <= threshold) {
            (Status::Critical, "expires within critical threshold")
        } else if warn_within.is_some_and(|threshold| remaining <= threshold) {
            (Status::Warning, "expires within warning threshold")
        } else {
            (Status::Ok, "within validity period")
        }
    };

    Assessment { status, reason }
}

pub(crate) struct Report<'a> {
    certs: &'a [Certificate],
    fields: &'a [Field],
    assessments: Vec<Assessment>,
    now: SystemTime,
}

impl<'a> Report<'a> {
    pub(crate) fn new(
        certs: &'a [Certificate],
        fields: &'a [Field],
        warn_within: Option<Duration>,
        critical_within: Option<Duration>,
    ) -> Self {
        let now = SystemTime::now();
        let assessments = certs
            .iter()
            .map(|cert| {
                assess(
                    cert.tbs_certificate().validity(),
                    now,
                    warn_within,
                    critical_within,
                )
            })
            .collect();

        Self {
            certs,
            fields,
            assessments,
            now,
        }
    }

    pub(crate) fn status(&self) -> Status {
        self.assessments
            .iter()
            .map(|assessment| assessment.status)
            .max()
            .unwrap_or(Status::Ok)
    }

    pub(crate) fn write_json(
        &self,
        mut writer: impl io::Write,
        check: bool,
        validation: Option<&validation::Report>,
    ) -> eyre::Result<()> {
        let fields = if self.fields.is_empty() {
            Field::value_variants()
        } else {
            self.fields
        };
        let certificates = self
            .certs
            .iter()
            .zip(&self.assessments)
            .map(|(cert, &assessment)| {
                fields
                    .iter()
                    .map(|&field| {
                        Ok((
                            field.name().to_owned(),
                            field.value(cert, assessment, self.now)?,
                        ))
                    })
                    .collect::<eyre::Result<Map<_, _>>>()
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        let mut value = json!({ "certificates": certificates });

        if check {
            value["check"] = json!({ "status": self.status().as_str() });
        }

        if let Some(validation) = validation {
            value["validation"] = validation.to_json(self.certs);
        }

        serde_json::to_writer_pretty(&mut writer, &value)?;
        writeln!(writer)?;

        Ok(())
    }

    pub(crate) fn write_fields(&self, mut writer: impl io::Write) -> eyre::Result<()> {
        for (cert, &assessment) in self.certs.iter().zip(&self.assessments) {
            writeln!(writer, "Certificate\n===========")?;

            for &field in self.fields {
                let value = field.value(cert, assessment, self.now)?;

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

    pub(crate) fn write_check(&self, mut writer: impl io::Write) -> io::Result<()> {
        for (index, assessment) in self.assessments.iter().enumerate() {
            writeln!(
                writer,
                "{}: certificate {}: {}",
                assessment.status.as_str().to_ascii_uppercase(),
                index + 1,
                assessment.reason
            )?;
        }

        writeln!(
            writer,
            "{}: {} certificates",
            self.status().as_str().to_ascii_uppercase(),
            self.certs.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validity(not_before: &str, not_after: &str) -> Validity {
        Validity::new(not_before.parse().unwrap(), not_after.parse().unwrap())
    }

    fn now() -> SystemTime {
        "2026-10-02T12:00:00Z"
            .parse::<x509_cert::time::Time>()
            .unwrap()
            .to_system_time()
    }

    #[test]
    fn validity_includes_both_endpoints() {
        for period in [
            validity("2026-10-02T12:00:00Z", "2026-10-03T12:00:00Z"),
            validity("2026-10-01T12:00:00Z", "2026-10-02T12:00:00Z"),
        ] {
            assert_eq!(assess(&period, now(), None, None).status, Status::Ok);
        }
    }

    #[test]
    fn expiry_thresholds_include_the_exact_boundary() {
        let period = validity("2026-10-01T12:00:00Z", "2026-10-03T12:00:00Z");
        let day = Duration::from_secs(86400);

        assert_eq!(
            assess(&period, now(), Some(day), None).status,
            Status::Warning
        );
        assert_eq!(
            assess(&period, now(), Some(day), Some(day)).status,
            Status::Critical
        );
    }

    #[test]
    fn expiry_thresholds_keep_subsecond_precision() {
        let period = validity("2026-10-01T12:00:00Z", "2026-10-02T12:00:01Z");
        let now = now() + Duration::from_millis(400);

        assert_eq!(
            assess(&period, now, Some(Duration::from_millis(500)), None).status,
            Status::Ok
        );
    }

    #[test]
    fn inverted_validity_period_is_critical() {
        let period = validity("2026-10-03T12:00:00Z", "2026-10-01T12:00:00Z");

        assert_eq!(
            assess(&period, now(), None, None).reason,
            "invalid validity period"
        );
    }
}
