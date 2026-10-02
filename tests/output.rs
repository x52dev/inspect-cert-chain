use std::{
    io::Write as _,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime},
};

use der::{
    Decode as _, Encode as _,
    asn1::{GeneralizedTime, UtcTime},
};
use serde_json::{Value, json};
use x509_cert::{Certificate, time::Time};

const CERTIFICATE: &[u8] = include_bytes!("fixtures/server.pem");

fn run(input: &[u8], args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
        .args(["--file", "-"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child.stdin.take().unwrap().write_all(input).unwrap();

    child.wait_with_output().unwrap()
}

fn certificate(not_before: SystemTime, not_after: SystemTime) -> String {
    let mut pem = CERTIFICATE;
    let der = rustls_pemfile::certs(&mut pem).next().unwrap().unwrap();
    let cert = Certificate::from_der(&der).unwrap();
    let validity = cert.tbs_certificate().validity();
    let mut bytes = der.to_vec();

    // Check mode tests dates only. Keep the fixture's signature and other fields.
    for (original, replacement) in [
        (validity.not_before, not_before),
        (validity.not_after, not_after),
    ] {
        let replacement = match original {
            Time::UtcTime(_) => Time::UtcTime(
                UtcTime::from_date_time(der::DateTime::try_from(replacement).unwrap()).unwrap(),
            ),
            Time::GeneralTime(_) => {
                Time::GeneralTime(GeneralizedTime::try_from(replacement).unwrap())
            }
        };
        let original = original.to_der().unwrap();
        let replacement = replacement.to_der().unwrap();
        assert_eq!(original.len(), replacement.len());

        let offsets = bytes
            .windows(original.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == original).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(offsets.len(), 1);

        let offset = offsets[0];
        bytes[offset..offset + original.len()].copy_from_slice(&replacement);
    }

    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &bytes).unwrap()
}

fn valid_certificate(expires_in: Duration) -> String {
    let now = SystemTime::now();

    certificate(now - Duration::from_secs(3600), now + expires_in)
}

#[test]
fn json_contains_structured_certificate_data() {
    let output = run(CERTIFICATE, &["--json", "-vv"]);

    assert!(output.status.success(), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let cert = &value["certificates"][0];

    assert_eq!(cert["subject"], "CN=localhost");
    assert_eq!(cert["issuer"], "CN=localhost");
    assert_eq!(cert["version"], 3);
    assert_eq!(cert["not_after"], "2126-09-07T17:25:48Z");
    assert_eq!(
        cert["subject_alt_names"],
        json!(["DNS:localhost", "IP:127.0.0.1"])
    );
    assert!(cert["expires_in_seconds"].is_number());
    assert!(cert["extensions"].is_array());
    assert_eq!(value["certificates"].as_array().unwrap().len(), 1);
    assert!(value.get("check").is_none());
    assert!(!output.stdout.contains(&0x1b));
}

#[test]
fn field_selection_omits_other_json_fields_for_each_certificate() {
    let chain = [CERTIFICATE, CERTIFICATE].concat();
    let output = run(&chain, &["--json", "--fields", "subject,issuer"]);

    assert!(output.status.success(), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(
        value,
        json!({
            "certificates": [
                {"subject": "CN=localhost", "issuer": "CN=localhost"},
                {"subject": "CN=localhost", "issuer": "CN=localhost"},
            ],
        })
    );
}

#[test]
fn field_selection_limits_text_output() {
    let output = run(CERTIFICATE, &["--fields", "subject"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Certificate\n===========\nsubject: CN=localhost\n\n"
    );
}

#[test]
fn repeated_field_options_keep_the_requested_text_order() {
    let output = run(
        CERTIFICATE,
        &["--fields", "not_after", "--fields", "subject"],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Certificate\n===========\nnot_after: 2126-09-07T17:25:48Z\nsubject: CN=localhost\n\n"
    );
}

#[test]
fn check_succeeds_when_all_dates_are_valid() {
    let cert = valid_certificate(Duration::from_secs(86400 * 90));
    let output = run(cert.as_bytes(), &["--check", "--json"]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["check"]["status"], "ok");
}

#[test]
fn check_returns_warning_within_warning_threshold() {
    let cert = valid_certificate(Duration::from_secs(86400 * 10));
    let output = run(
        cert.as_bytes(),
        &[
            "--check",
            "--json",
            "--warn-within",
            "30d",
            "--critical-within",
            "7d",
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["check"]["status"], "warning");
    assert_eq!(
        value["certificates"][0]["status"]["reason"],
        "expires within warning threshold"
    );
}

#[test]
fn critical_status_takes_precedence_over_warning_across_the_chain() {
    let warning = valid_certificate(Duration::from_secs(86400 * 10));
    let critical = valid_certificate(Duration::from_secs(86400 * 2));
    let chain = warning + &critical;
    let output = run(
        chain.as_bytes(),
        &[
            "--check",
            "--json",
            "--fields",
            "subject",
            "--warn-within",
            "30d",
            "--critical-within",
            "7d",
        ],
    );

    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["check"]["status"], "critical");
    assert_eq!(value["certificates"][1], json!({"subject": "CN=localhost"}));
}

#[test]
fn check_reports_expired_certificates() {
    let now = SystemTime::now();
    let cert = certificate(
        now - Duration::from_secs(7200),
        now - Duration::from_secs(3600),
    );
    let output = run(cert.as_bytes(), &["--check"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("CRITICAL: certificate 1: expired"));
}

#[test]
fn check_reports_certificates_that_are_not_yet_valid() {
    let now = SystemTime::now();
    let cert = certificate(
        now + Duration::from_secs(3600),
        now + Duration::from_secs(7200),
    );
    let output = run(cert.as_bytes(), &["--check", "--json"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["certificates"][0]["status"]["reason"],
        "not yet valid"
    );
}

#[test]
fn inspection_does_not_fail_for_expired_certificates_without_check() {
    let now = SystemTime::now();
    let cert = certificate(
        now - Duration::from_secs(7200),
        now - Duration::from_secs(3600),
    );
    let output = run(cert.as_bytes(), &["--json"]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value["certificates"][0]["expires_in_seconds"]
            .as_i64()
            .unwrap()
            < 0
    );
}

#[test]
fn help_and_version_succeed_without_an_input_source() {
    for arg in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
            .arg(arg)
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn check_input_errors_use_unknown_exit_code_and_json() {
    for input in [
        b"".as_slice(),
        b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
    ] {
        let output = run(input, &["--check", "--json"]);

        assert_eq!(output.status.code(), Some(3), "{output:?}");

        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["check"]["status"], "unknown");
        assert!(value["error"].is_string());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn invalid_options_are_rejected_before_reading_input() {
    for args in [
        vec!["--interactive", "--json"],
        vec!["--interactive", "--fields", "subject"],
        vec!["--interactive", "--check"],
        vec!["--fields", "unknown"],
        vec!["--fields", ""],
        vec!["--warn-within", "30d"],
        vec!["--check", "--warn-within", "-1d"],
        vec!["--check", "--critical-within", "invalid"],
        vec!["--check", "--warn-within", "7d", "--critical-within", "30d"],
    ] {
        let output = run(b"", &args);

        assert_eq!(output.status.code(), Some(3), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("error:"),
            "{args:?}: {output:?}"
        );
    }
}
