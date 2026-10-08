use std::process::Command;

fn inspect(host: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_inspect-cert-chain"))
        .args(["--host", host, "--timeout", "30s"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{host}: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    String::from_utf8(output.stdout).unwrap()
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn incomplete_chain_reports_the_missing_issuer() {
    let stdout = inspect("incomplete-chain.badssl.com");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("missing issuer certificate"), "{stdout}");
    assert!(
        stdout.contains("Hostname (incomplete-chain.badssl.com): VALID"),
        "{stdout}"
    );
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn revoked_certificate_reports_revocation() {
    let stdout = inspect("revoked.badssl.com");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Revocation (leaf): INVALID (certificate revoked)"),
        "{stdout}"
    );
    assert!(stdout.contains("Path validation: VALID"), "{stdout}");
    assert!(
        stdout.contains("Hostname (revoked.badssl.com): VALID"),
        "{stdout}"
    );
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn expired_certificate_reports_expiry() {
    let stdout = inspect("expired.badssl.com");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Path validation: INVALID (certificate expired)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Certificate 1 dates: INVALID (expired)"),
        "{stdout}"
    );
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn wrong_hostname_reports_name_mismatch() {
    let stdout = inspect("wrong.host.badssl.com");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(stdout.contains("Path validation: VALID"), "{stdout}");
    assert!(
        stdout.contains(
            "Hostname (wrong.host.badssl.com): INVALID (hostname does not match certificate names)"
        ),
        "{stdout}"
    );
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn self_signed_certificate_reports_missing_trust() {
    let stdout = inspect("self-signed.badssl.com");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Path validation: INVALID (self-issued certificate is not trusted)"),
        "{stdout}"
    );
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn untrusted_root_reports_missing_trust() {
    let stdout = inspect("untrusted-root.badssl.com");

    assert!(stdout.contains("Certificate chain: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Path validation: INVALID (root CA is not trusted)"),
        "{stdout}"
    );
}

#[test]
#[ignore = "requires access to the public badssl.com test service"]
fn trusted_control_reports_validity() {
    let stdout = inspect("sha256.badssl.com");

    assert!(stdout.contains("Certificate chain: VALID"), "{stdout}");
    assert!(stdout.contains("Path validation: VALID"), "{stdout}");
    assert!(stdout.contains("Revocation (leaf): VALID"), "{stdout}");
}
