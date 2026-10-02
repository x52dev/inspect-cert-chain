use std::{
    io,
    time::{Duration, SystemTime},
};

use x509_cert::{Certificate, time::Validity};

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
    assessments: Vec<Assessment>,
}

impl<'a> Report<'a> {
    pub(crate) fn new(
        certs: &'a [Certificate],
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

        Self { certs, assessments }
    }

    pub(crate) fn status(&self) -> Status {
        self.assessments
            .iter()
            .map(|assessment| assessment.status)
            .max()
            .unwrap_or(Status::Ok)
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
