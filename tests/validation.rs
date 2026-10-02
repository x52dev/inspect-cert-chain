use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpListener,
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, date_time_ymd,
};

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();

    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    params
}

fn root() -> (Certificate, Issuer<'static, KeyPair>) {
    let params = ca_params("Test root");
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    (cert, Issuer::new(params, key))
}

fn leaf_params() -> CertificateParams {
    let mut params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();

    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    params
}

fn check(chain: &str, roots: &[&str], hostname: &str) -> String {
    check_with_crls(chain, roots, hostname, &[])
}

fn check_with_crls(chain: &str, roots: &[&str], hostname: &str, crls: &[&[u8]]) -> String {
    let output = local_output(chain, roots, hostname, crls, &[]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );

    String::from_utf8(output.stdout).unwrap()
}

fn local_output(
    chain: &str,
    roots: &[&str],
    hostname: &str,
    crls: &[&[u8]],
    args: &[&str],
) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let chain_path = dir.path().join("chain.pem");

    fs::write(&chain_path, chain).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"));

    cmd.arg("--file")
        .arg(&chain_path)
        .args(["--check", "--hostname", hostname]);

    for (index, root) in roots.iter().enumerate() {
        let path = dir.path().join(format!("root-{index}.pem"));

        fs::write(&path, root).unwrap();
        cmd.arg("--ca-file").arg(path);
    }

    for (index, crl) in crls.iter().enumerate() {
        let path = dir.path().join(format!("revocations-{index}.crl"));

        fs::write(&path, crl).unwrap();
        cmd.arg("--crl-file").arg(path);
    }

    cmd.args(args).output().unwrap()
}

fn crl_params(revoked: bool) -> rcgen::CertificateRevocationListParams {
    rcgen::CertificateRevocationListParams {
        this_update: date_time_ymd(2000, 1, 1),
        next_update: date_time_ymd(4096, 1, 1),
        crl_number: 1.into(),
        issuing_distribution_point: None,
        revoked_certs: if revoked {
            vec![rcgen::RevokedCertParams {
                serial_number: 42.into(),
                revocation_time: date_time_ymd(2000, 1, 1),
                reason_code: None,
                invalidity_date: None,
            }]
        } else {
            vec![]
        },
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
}

#[test]
fn signed_crls_report_revoked_and_unrevoked_certificates() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.serial_number = Some(42.into());

    let leaf = params.signed_by(&key, &issuer).unwrap();

    for revoked in [false, true] {
        let crl = crl_params(revoked).signed_by(&issuer).unwrap();
        let pem = crl.pem().unwrap();

        for bytes in [crl.der().as_ref(), pem.as_bytes()] {
            let stdout = check_with_crls(&leaf.pem(), &[&root.pem()], "localhost", &[bytes]);
            let status = if revoked {
                "INVALID (certificate revoked)"
            } else {
                "VALID"
            };
            let chain_status = if revoked { "INVALID" } else { "VALID" };

            assert!(
                stdout.contains(&format!("Revocation (leaf): {status}")),
                "{stdout}"
            );
            assert!(
                stdout.contains(&format!("Certificate chain: {chain_status}")),
                "{stdout}"
            );
            assert!(stdout.contains("Path validation: VALID"), "{stdout}");
        }
    }
}

#[test]
fn unauthenticated_or_outdated_crls_do_not_claim_a_revocation_status() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.serial_number = Some(42.into());

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let mut tampered = crl_params(true).signed_by(&issuer).unwrap().der().to_vec();

    *tampered.last_mut().unwrap() ^= 1;

    let mut expired_params = crl_params(true);

    expired_params.next_update = date_time_ymd(2001, 1, 1);

    let expired = expired_params.signed_by(&issuer).unwrap();
    let mut future_params = crl_params(true);

    future_params.this_update = date_time_ymd(3000, 1, 1);

    let future = future_params.signed_by(&issuer).unwrap();
    let mut unrelated_params = ca_params("Unrelated CRL issuer");
    let key = KeyPair::generate().unwrap();

    unrelated_params.serial_number = Some(100.into());

    let unrelated_issuer = Issuer::new(unrelated_params, key);
    let unrelated = crl_params(true).signed_by(&unrelated_issuer).unwrap();

    for (bytes, reason) in [
        (tampered.as_slice(), "invalid CRL signature"),
        (expired.der().as_ref(), "CRL expired"),
        (future.der().as_ref(), "CRL is not yet valid"),
        (unrelated.der().as_ref(), "no authoritative CRL"),
    ] {
        let stdout = check_with_crls(&leaf.pem(), &[&root.pem()], "localhost", &[bytes]);

        assert!(stdout.contains("Certificate chain: UNKNOWN"), "{stdout}");
        assert!(stdout.contains("Revocation (leaf): UNKNOWN"), "{stdout}");
        assert!(stdout.contains(reason), "{stdout}");
    }
}

#[test]
fn crl_scope_must_cover_the_leaf_distribution_point() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.serial_number = Some(42.into());
    params
        .crl_distribution_points
        .push(rcgen::CrlDistributionPoint {
            uris: vec!["http://crl.example/leaf.crl".to_owned()],
        });

    let leaf = params.signed_by(&key, &issuer).unwrap();

    for (url, scope) in [
        (
            "http://crl.example/other.crl",
            rcgen::CrlScope::UserCertsOnly,
        ),
        ("http://crl.example/leaf.crl", rcgen::CrlScope::CaCertsOnly),
    ] {
        let mut params = crl_params(true);

        params.issuing_distribution_point = Some(rcgen::CrlIssuingDistributionPoint {
            distribution_point: rcgen::CrlDistributionPoint {
                uris: vec![url.to_owned()],
            },
            scope: Some(scope),
        });

        let crl = params.signed_by(&issuer).unwrap();
        let stdout = check_with_crls(
            &leaf.pem(),
            &[&root.pem()],
            "localhost",
            &[crl.der().as_ref()],
        );

        assert!(stdout.contains("Certificate chain: UNKNOWN"), "{stdout}");
        assert!(
            stdout.contains("Revocation (leaf): UNKNOWN (no authoritative CRL"),
            "{stdout}"
        );
    }
}

#[test]
fn crl_bundles_and_repeated_files_use_the_newest_authoritative_crl() {
    let (root, issuer) = root();
    let (_, unrelated_issuer) = self::root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.serial_number = Some(42.into());

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let older = crl_params(false).signed_by(&issuer).unwrap();
    let mut params = crl_params(true);

    params.this_update = date_time_ymd(2001, 1, 1);
    params.crl_number = 2.into();

    let newer = params.signed_by(&issuer).unwrap();
    let unrelated = crl_params(false).signed_by(&unrelated_issuer).unwrap();
    let bundle = older.pem().unwrap() + &unrelated.pem().unwrap() + &newer.pem().unwrap();

    for crls in [
        vec![
            older.der().as_ref(),
            unrelated.der().as_ref(),
            newer.der().as_ref(),
        ],
        vec![newer.der().as_ref(), older.der().as_ref()],
        vec![bundle.as_bytes()],
    ] {
        let stdout = check_with_crls(&leaf.pem(), &[&root.pem()], "localhost", &crls);

        assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
        assert!(
            stdout.contains("Revocation (leaf): INVALID (certificate revoked)"),
            "{stdout}"
        );
    }
}

#[test]
fn custom_ca_file_trusts_a_valid_chain() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let stdout = check(&leaf.pem(), &[&root.pem()], "localhost");

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    assert!(stdout.contains("Hostname (localhost): VALID"), "{stdout}");
    assert!(stdout.contains("Certificate 1 dates: VALID"), "{stdout}");
}

#[test]
fn a_root_in_the_chain_is_not_a_trust_anchor() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let stdout = check(&(leaf.pem() + &root.pem()), &[], "localhost");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("root CA is not trusted"), "{stdout}");
}

#[test]
fn a_missing_intermediate_is_reported() {
    let (root, root_issuer) = root();
    let params = ca_params("Missing intermediate");
    let key = KeyPair::generate().unwrap();
    let _intermediate = params.signed_by(&key, &root_issuer).unwrap();
    let issuer = Issuer::new(params, key);
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let stdout = check(&leaf.pem(), &[&root.pem()], "localhost");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("missing issuer certificate"), "{stdout}");
}

#[test]
fn an_untrusted_self_issued_certificate_is_reported() {
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().self_signed(&key).unwrap();
    let stdout = check(&leaf.pem(), &[], "localhost");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("self-issued certificate is not trusted"),
        "{stdout}"
    );
}

#[test]
fn hostname_mismatch_is_reported_without_rejecting_the_chain() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let stdout = check(&leaf.pem(), &[&root.pem()], "wrong.example");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Hostname (wrong.example): INVALID"),
        "{stdout}"
    );
}

#[test]
fn json_validation_preserves_field_selection_and_date_thresholds() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let output = local_output(
        &leaf.pem(),
        &[&root.pem()],
        "wrong.example",
        &[],
        &["--json", "--fields", "subject", "--warn-within", "1000000d"],
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(
        value["certificates"],
        serde_json::json!([{ "subject": "CN=localhost" }])
    );
    assert_eq!(value["check"]["status"], "warning");
    assert_eq!(value["validation"]["status"], "invalid");
    assert_eq!(value["validation"]["path"]["status"], "valid");
    assert_eq!(value["validation"]["hostname"]["name"], "wrong.example");
    assert_eq!(
        value["validation"]["hostname"]["reason"],
        "hostname does not match certificate names"
    );
    assert_eq!(value["validation"]["dates"][0]["status"], "valid");
    assert_eq!(value["validation"]["revocation"]["status"], "not_checked");
    assert!(value["validation"].get("handshake_signature").is_none());
}

#[test]
fn json_reports_signed_and_unverified_revocation_results() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.serial_number = Some(42.into());

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let valid = crl_params(false).signed_by(&issuer).unwrap();
    let revoked = crl_params(true).signed_by(&issuer).unwrap();
    let mut invalid = revoked.der().to_vec();

    *invalid.last_mut().unwrap() ^= 1;

    for (crl, status, reason) in [
        (valid.der().as_ref(), "valid", None),
        (
            revoked.der().as_ref(),
            "invalid",
            Some("certificate revoked"),
        ),
        (invalid.as_slice(), "unknown", Some("invalid CRL signature")),
    ] {
        let output = local_output(
            &leaf.pem(),
            &[&root.pem()],
            "localhost",
            &[crl],
            &["--json"],
        );

        assert_eq!(output.status.code(), Some(0), "{output:?}");

        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

        assert_eq!(value["validation"]["status"], status);
        assert_eq!(value["validation"]["revocation"]["status"], status);
        assert_eq!(value["validation"]["revocation"]["reason"].as_str(), reason);
        assert_eq!(value["validation"]["path"]["status"], "valid");
        assert_eq!(value["check"]["status"], "ok");
    }
}

#[test]
fn ip_address_subject_alternative_names_are_checked() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let stdout = check(&leaf.pem(), &[&root.pem()], "127.0.0.1");

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    assert!(stdout.contains("Hostname (127.0.0.1): VALID"), "{stdout}");
}

#[test]
fn expired_certificate_dates_are_reported() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.not_before = date_time_ymd(1999, 1, 1);
    params.not_after = date_time_ymd(2000, 1, 1);

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let output = local_output(&leaf.pem(), &[&root.pem()], "localhost", &[], &[]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Certificate 1 dates: INVALID (expired)"),
        "{stdout}"
    );
}

#[test]
fn future_certificate_dates_are_reported() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();

    params.not_before = date_time_ymd(2100, 1, 1);

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let output = local_output(&leaf.pem(), &[&root.pem()], "localhost", &[], &[]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Certificate 1 dates: INVALID (not yet valid)"),
        "{stdout}"
    );
}

#[test]
fn a_tampered_certificate_signature_is_reported() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let mut der = leaf.der().to_vec();

    *der.last_mut().unwrap() ^= 1;

    let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der).unwrap();
    let stdout = check(&pem, &[&root.pem()], "localhost");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("Hostname (localhost): VALID"), "{stdout}");
}

fn check_intermediate(params: CertificateParams) -> String {
    let (root, root_issuer) = root();
    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate = params.signed_by(&intermediate_key, &root_issuer).unwrap();
    let intermediate_issuer = Issuer::new(params, intermediate_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params()
        .signed_by(&leaf_key, &intermediate_issuer)
        .unwrap();

    check(
        &(leaf.pem() + &intermediate.pem()),
        &[&root.pem()],
        "localhost",
    )
}

#[test]
fn a_valid_intermediate_ca_is_accepted() {
    let stdout = check_intermediate(ca_params("Intermediate"));

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
}

#[test]
fn an_intermediate_must_be_a_ca() {
    let mut params = ca_params("Intermediate");

    params.is_ca = IsCa::ExplicitNoCa;

    let stdout = check_intermediate(params);

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
}

#[test]
fn an_intermediate_must_allow_certificate_signing() {
    let mut params = ca_params("Intermediate");

    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let stdout = check_intermediate(params);

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
}

#[test]
fn ca_name_constraints_are_checked() {
    let mut params = ca_params("Intermediate");

    params.name_constraints = Some(rcgen::NameConstraints {
        permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("allowed.example".into())],
        excluded_subtrees: vec![],
    });

    let stdout = check_intermediate(params);

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
}

#[test]
fn unknown_critical_extensions_are_reported() {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut params = leaf_params();
    let mut extension = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![0x05, 0x00]);

    extension.set_criticality(true);
    params.custom_extensions.push(extension);

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let stdout = check(&leaf.pem(), &[&root.pem()], "localhost");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
}

#[test]
fn a_valid_alternative_path_can_bypass_an_invalid_ca_key_usage() {
    let (root, root_issuer) = root();
    let key = KeyPair::generate().unwrap();
    let mut good_params = ca_params("Alternate intermediate");

    good_params.serial_number = Some(2.into());

    let good = good_params.signed_by(&key, &root_issuer).unwrap();
    let mut bad_params = good_params.clone();

    bad_params.serial_number = Some(3.into());
    bad_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let bad = bad_params.signed_by(&key, &root_issuer).unwrap();
    let issuer = Issuer::new(good_params, key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&leaf_key, &issuer).unwrap();
    let chain = leaf.pem() + &bad.pem() + &good.pem();
    let stdout = check(&chain, &[&root.pem()], "localhost");

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
}

#[test]
fn system_trust_roots_are_used_and_custom_ca_files_add_to_them() {
    let (root, issuer) = root();
    let (custom_root, _) = self::root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let chain_path = dir.path().join("chain.pem");
    let root_path = dir.path().join("system-root.pem");
    let custom_path = dir.path().join("custom-root.pem");
    let empty_ca_dir = dir.path().join("empty-ca-dir");

    fs::write(&chain_path, leaf.pem()).unwrap();
    fs::write(&root_path, root.pem()).unwrap();
    fs::write(&custom_path, custom_root.pem()).unwrap();
    fs::create_dir(&empty_ca_dir).unwrap();

    for add_custom_root in [false, true] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"));

        cmd.arg("--file")
            .arg(&chain_path)
            .args(["--check", "--hostname", "localhost"])
            .env("SSL_CERT_FILE", &root_path)
            .env("SSL_CERT_DIR", &empty_ca_dir);

        if add_custom_root {
            cmd.arg("--ca-file").arg(&custom_path);
        }

        let output = cmd.output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    }
}

#[test]
fn stdin_chain_checks_show_statuses() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
        .args(["--file", "-", "--check", "--hostname", "localhost"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(include_bytes!("fixtures/server.pem"))
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("Hostname (localhost): VALID"), "{stdout}");
}

#[test]
fn hostname_and_ca_files_require_local_validation() {
    for extra in [
        vec!["--hostname", "localhost"],
        vec!["--ca-file", "ca.pem"],
        vec!["--check", "--ca-file", "ca.pem"],
        vec!["--check", "--crl-file", "issuer.crl"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
            .args([
                "--file",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/server.pem"),
            ])
            .args(extra)
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("required arguments"));
    }
}

#[test]
fn ca_path_length_constraints_are_checked() {
    let (root, root_issuer) = root();
    let mut params = ca_params("Intermediate");

    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

    let key = KeyPair::generate().unwrap();
    let intermediate = params.signed_by(&key, &root_issuer).unwrap();
    let issuer = Issuer::new(params, key);
    let params = ca_params("Subordinate CA");
    let key = KeyPair::generate().unwrap();
    let subordinate = params.signed_by(&key, &issuer).unwrap();
    let issuer = Issuer::new(params, key);
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();
    let chain = leaf.pem() + &subordinate.pem() + &intermediate.pem();
    let stdout = check(&chain, &[&root.pem()], "localhost");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
}

#[test]
fn repeated_ca_files_and_pem_bundles_are_supported() {
    let (root, issuer) = root();
    let (unrelated_root, _) = self::root();
    let key = KeyPair::generate().unwrap();
    let leaf = leaf_params().signed_by(&key, &issuer).unwrap();

    for roots in [
        vec![unrelated_root.pem(), root.pem()],
        vec![unrelated_root.pem() + &root.pem()],
    ] {
        let roots = roots.iter().map(String::as_str).collect::<Vec<_>>();
        let stdout = check(&leaf.pem(), &roots, "localhost");

        assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    }
}

#[test]
fn invalid_ca_files_are_input_errors() {
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");

    for (pem, error) in [
        ("", "CA file contained 0 certificates"),
        (
            "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
            "Could not read CA certificates",
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            "Invalid CA certificate",
        ),
    ] {
        fs::write(&ca_path, pem).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
            .args([
                "--file",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/server.pem"),
                "--check",
                "--hostname",
                "localhost",
                "--ca-file",
            ])
            .arg(&ca_path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(!output.status.success(), "Invalid CA file was accepted");
        assert!(stderr.contains(error), "{stderr}");
    }
}

#[derive(Debug)]
struct BadSigningKey(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for BadSigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(BadSigner(signer)) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct BadSigner(Box<dyn rustls::sign::Signer>);

impl rustls::sign::Signer for BadSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;

        *signature.last_mut().unwrap() ^= 1;

        Ok(signature)
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.0.scheme()
    }
}

#[derive(Clone, Copy)]
enum CrlResponse {
    Unrevoked,
    Revoked,
    InvalidSignature,
    Unavailable,
    Delayed,
}

fn serve_crl(
    issuer: &Issuer<'_, KeyPair>,
    response: CrlResponse,
) -> (String, thread::JoinHandle<()>) {
    let crl = crl_params(!matches!(response, CrlResponse::Unrevoked))
        .signed_by(issuer)
        .unwrap();
    let mut bytes = crl.der().to_vec();

    if matches!(response, CrlResponse::InvalidSignature) {
        *bytes.last_mut().unwrap() ^= 1;
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/revocations.crl", listener.local_addr().unwrap());

    listener.set_nonblocking(true).unwrap();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CRL was not requested");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("CRL server accept failed: {error}"),
            }
        };

        socket.set_nonblocking(false).unwrap();

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut request = [0; 1024];

        assert!(socket.read(&mut request).unwrap() > 0);

        if matches!(response, CrlResponse::Delayed) {
            thread::sleep(Duration::from_secs(6));
            return;
        }

        let status = if matches!(response, CrlResponse::Unavailable) {
            "503 Service Unavailable"
        } else {
            "200 OK"
        };

        write!(
            socket,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )
        .unwrap();
        socket.write_all(&bytes).unwrap();
    });

    (url, server)
}

fn inspect_remote(
    version: &'static rustls::SupportedProtocolVersion,
    bad_signature: bool,
    crl_response: Option<CrlResponse>,
) -> String {
    let (root, issuer) = root();
    let key = KeyPair::generate().unwrap();
    let crl_server = crl_response.map(|response| serve_crl(&issuer, response));
    let mut params = leaf_params();

    params.serial_number = Some(42.into());

    if let Some((url, _)) = &crl_server {
        params
            .crl_distribution_points
            .push(rcgen::CrlDistributionPoint {
                uris: vec![url.clone()],
            });
    }

    let leaf = params.signed_by(&key, &issuer).unwrap();
    let key_der = rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let mut signing_key =
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der.into()).unwrap();

    if bad_signature {
        signing_key = Arc::new(BadSigningKey(signing_key));
    }

    let certified_key = rustls::sign::CertifiedKey::new(vec![leaf.der().clone()], signing_key);
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
        certified_key,
    )));

    config.send_tls13_tickets = 0;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    listener.set_nonblocking(true).unwrap();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);

        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Client did not connect");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("Server accept failed: {err}"),
            }
        };

        socket.set_nonblocking(false).unwrap();

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, socket);
        tls.conn.complete_io(&mut tls.sock).unwrap();

        assert_eq!(tls.conn.server_name(), Some("localhost"));
    });

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let dump_path = dir.path().join("downloaded.pem");

    fs::write(&ca_path, root.pem()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
        .args([
            "--host",
            "127.0.0.1",
            "--server-name",
            "localhost",
            "--port",
            &port.to_string(),
            "--timeout",
            "5s",
            "--ca-file",
        ])
        .arg(ca_path)
        .arg("--dump")
        .arg(&dump_path)
        .output()
        .unwrap();

    server.join().unwrap();

    if let Some((_, server)) = crl_server {
        server.join().unwrap();
    }

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dumped = fs::read(&dump_path).unwrap();
    let dumped = rustls_pemfile::certs(&mut dumped.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(dumped, vec![leaf.der().clone()]);

    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn remote_custom_ca_checks_support_tls12() {
    let stdout = inspect_remote(&rustls::version::TLS12, false, Some(CrlResponse::Unrevoked));

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    assert!(stdout.contains("Hostname (localhost): VALID"), "{stdout}");
    assert!(
        stdout.contains("TLS handshake signature: VALID"),
        "{stdout}"
    );
}

#[test]
fn remote_custom_ca_checks_support_tls13() {
    let stdout = inspect_remote(&rustls::version::TLS13, false, Some(CrlResponse::Unrevoked));

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    assert!(stdout.contains("Hostname (localhost): VALID"), "{stdout}");
    assert!(
        stdout.contains("TLS handshake signature: VALID"),
        "{stdout}"
    );
}

#[test]
fn invalid_tls_handshake_signatures_are_reported_and_the_chain_is_dumped() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let stdout = inspect_remote(version, true, None);

        assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
        assert!(
            stdout.contains("TLS handshake signature: INVALID"),
            "{stdout}"
        );
    }
}

#[test]
fn remote_revoked_certificates_are_reported_and_dumped() {
    let stdout = inspect_remote(&rustls::version::TLS13, false, Some(CrlResponse::Revoked));

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Revocation (leaf): INVALID (certificate revoked)"),
        "{stdout}"
    );
    assert!(stdout.contains("Path validation: VALID"), "{stdout}");
}

#[test]
fn remote_unknown_revocation_does_not_reject_the_fetch() {
    for response in [
        None,
        Some(CrlResponse::InvalidSignature),
        Some(CrlResponse::Unavailable),
        Some(CrlResponse::Delayed),
    ] {
        let stdout = inspect_remote(&rustls::version::TLS13, false, response);

        assert!(stdout.contains("Certificate chain: UNKNOWN"), "{stdout}");
        assert!(stdout.contains("Revocation (leaf): UNKNOWN"), "{stdout}");
        assert!(stdout.contains("Path validation: VALID"), "{stdout}");
    }
}
