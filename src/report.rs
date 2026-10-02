use std::{io, time::SystemTime};

use eyre::WrapErr as _;
use itertools::Itertools as _;
use serde_json::{Value, json};
use x509_cert::{Certificate, ext::pkix::SubjectAltName};

use crate::{ext, util};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).join("")
}

fn certificate_value(cert: &Certificate, now: SystemTime) -> eyre::Result<Value> {
    let tbs = cert.tbs_certificate();
    let expiry = tbs.validity().not_after.to_system_time();
    let seconds = match expiry.duration_since(now) {
        Ok(remaining) => remaining.as_secs() as i64,
        Err(elapsed) => {
            let elapsed = elapsed.duration();

            -(elapsed.as_secs() as i64) - i64::from(elapsed.subsec_nanos() > 0)
        }
    };
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
    let spki = tbs.subject_public_key_info();
    let extensions = tbs
        .extensions()
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
        .collect::<Vec<_>>();

    Ok(json!({
        "subject": tbs.subject().to_string(),
        "issuer": tbs.issuer().to_string(),
        "version": tbs.version() as u8 + 1,
        "serial_number": hex(tbs.serial_number().as_bytes()),
        "signature_algorithm": {
            "oid": cert.signature_algorithm().oid.to_string(),
            "name": util::oid_desc_or_raw(&cert.signature_algorithm().oid),
        },
        "not_before": tbs.validity().not_before.to_string(),
        "not_after": tbs.validity().not_after.to_string(),
        "expires_in_seconds": seconds,
        "subject_alt_names": names,
        "public_key": {
            "algorithm": {
                "oid": spki.algorithm.oid.to_string(),
                "name": util::oid_desc_or_raw(&spki.algorithm.oid),
            },
            "value": hex(spki.subject_public_key.raw_bytes()),
        },
        "extensions": extensions,
        "signature": hex(cert.signature().raw_bytes()),
    }))
}

pub(crate) fn write_json(certs: &[Certificate], mut writer: impl io::Write) -> eyre::Result<()> {
    let now = SystemTime::now();
    let certificates = certs
        .iter()
        .map(|cert| certificate_value(cert, now))
        .collect::<eyre::Result<Vec<_>>>()?;
    let value = json!({ "certificates": certificates });

    serde_json::to_writer_pretty(&mut writer, &value)?;
    writeln!(writer)?;

    Ok(())
}
