use const_oid::{
    ObjectIdentifier,
    db::{DB, rfc5280, rfc5912, rfc6962},
};
use itertools::Itertools as _;
use x509_cert::spki::AlgorithmIdentifierOwned;

#[track_caller]
pub(crate) fn assert_null_params(alg: &AlgorithmIdentifierOwned) {
    assert!(alg.parameters.is_none() || alg.parameters.as_ref().unwrap().is_null());
}

pub(crate) fn oid_desc_or_raw(oid: &ObjectIdentifier) -> String {
    get_oid_desc(oid)
        .or(DB.by_oid(oid))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| oid.to_string())
}

/// Returns formatted date and true if date is in the future.
pub(crate) fn duration_since_now_fmt(time: x509_cert::time::Time) -> (String, bool) {
    use chrono::{DateTime, Utc};

    let ts = time.to_unix_duration().as_secs() as i64;

    let date = DateTime::from_timestamp(ts, 0).unwrap();
    let now = Utc::now();

    let duration = if now > date { now - date } else { date - now };

    let days = duration.num_days();

    if now > date {
        (format!("{days} days ago"), false)
    } else {
        (format!("in {days} days"), true)
    }
}

pub(crate) fn openssl_hex(bytes: &[u8], width: usize) -> impl Iterator<Item = String> + '_ {
    let n_chunks = bytes.len().div_ceil(width);

    bytes.chunks(width).enumerate().map(move |(i, chunk)| {
        let mut chunk = chunk.iter().map(|byte| format!("{byte:0>2x}:")).join("");
        if i + 1 == n_chunks {
            let _ = chunk.pop();
        }
        chunk
    })
}

fn get_oid_desc(oid: &ObjectIdentifier) -> Option<&str> {
    OID_DESCS
        .iter()
        .find(|&&(&id, _)| id == *oid)
        .map(|&(_, desc)| desc)
}

/// Contains human readable descriptions for commonly used OIDs.
const OID_DESCS: &[(&ObjectIdentifier, &str)] = &[
    (
        &rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        "Subject Key Identifier",
    ),
    (
        &rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        "Authority Key Identifier",
    ),
    (&rfc5280::ID_CE_KEY_USAGE, "Key Usage"),
    (&rfc5280::ID_CE_EXT_KEY_USAGE, "Extended Key Usage"),
    (&rfc5280::ID_CE_SUBJECT_ALT_NAME, "Subject Alternate Name"),
    (&rfc5912::ID_KP_CLIENT_AUTH, "Client Authentication"),
    (&rfc5912::ID_KP_SERVER_AUTH, "Server Authentication"),
    (&rfc5912::ID_CE_BASIC_CONSTRAINTS, "Basic Constraints"),
    (
        &rfc5912::ID_PE_AUTHORITY_INFO_ACCESS,
        "Authority Information Access",
    ),
    (
        &rfc5912::ID_CE_CRL_DISTRIBUTION_POINTS,
        "CRL Distribution Points",
    ),
    (&rfc5912::ID_CE_CERTIFICATE_POLICIES, "Certificate Policies"),
    (&rfc5912::ID_AD_OCSP, "OCSP"),
    (&rfc5912::ID_AD_CA_ISSUERS, "CA Issuers"),
    (&rfc6962::CT_PRECERT_SCTS, "CT Precertificate SCTs"),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.1"),
        "Extended Validation (EV) Guidelines",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.2.1"),
        "Domain Validated",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.2.2"),
        "Organization Validated",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.23.140.1.2.3"),
        "Individual Validated",
    ),
    (
        &ObjectIdentifier::new_unwrap("2.16.840.1.114412.2.1"),
        "DigiCert Extended Validation (EV) Guidelines",
    ),
    (
        &ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.31"),
        "ACME Identifier",
    ),
];

#[cfg(test)]
mod tests {
    use super::openssl_hex;

    #[test]
    fn openssl_hex_formats_partial_and_complete_chunks() {
        for (bytes, expected) in [
            ([].as_slice(), vec![]),
            ([0x01].as_slice(), vec!["01"]),
            ([0x01, 0x02].as_slice(), vec!["01:02"]),
            ([0x01, 0x02, 0x03].as_slice(), vec!["01:02:", "03"]),
            ([0x01, 0x02, 0x03, 0x04].as_slice(), vec!["01:02:", "03:04"]),
            (
                [0x01, 0x02, 0x03, 0x04, 0x05].as_slice(),
                vec!["01:02:", "03:04:", "05"],
            ),
        ] {
            assert_eq!(openssl_hex(bytes, 2).collect::<Vec<_>>(), expected);
        }
    }
}
