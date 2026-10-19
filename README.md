# `inspect-cert-chain`

> Inspect and debug TLS certificate chains (without OpenSSL)

[![Chat on Discord](https://img.shields.io/discord/1554698838651179088?label=chat&logo=discord)](https://discord.gg/F2KUuy5UH2)

[![asciicast](https://asciinema.org/a/657965.svg)](https://asciinema.org/a/657965)

# Install

With [`Homebrew`]:

```console
$ brew install x52dev/tap/inspect-cert-chain
```

With [`cargo-binstall`]:

```console
$ cargo binstall inspect-cert-chain
```

From source:

```console
$ cargo install inspect-cert-chain
```

# Usage

From a remote TLS server:

```console
inspect-cert-chain --host <hostname>
```

Remote fetching gets the certificate chain from the TLS handshake. It supports any application protocol on servers that start TLS as soon as the connection opens.

The default port is `443`. Use `--port` to inspect a TLS service on another port:

```console
inspect-cert-chain --host <hostname> --port <port>
```

Services that require a plaintext exchange before TLS, such as STARTTLS, are not supported.

To connect to a specific IP address with a different TLS server name (SNI):

```console
inspect-cert-chain --host 192.0.2.10 --server-name staging.example.com
```

`--host` selects the connection target. `--server-name` sets the TLS server name and the name used for certificate validation; it defaults to `--host` and requires `--host`. IPv6 addresses are also supported, for example `--host 2001:db8::10`.

Remote fetching has a `10s` overall timeout. Use `--timeout <DURATION>` to change it, for example `500ms`, `30s`, or `2m`. The duration must be greater than zero.

Remote chains always include validation status in text, JSON, and interactive output. Invalid chains remain available for inspection and `--dump`. Trust, hostname, signature, and revocation failures do not change the exit status. Date failures change the exit status only with `--check`. Connection, timeout, and input errors still cause a nonzero exit status.

Path validation uses WebPKI to check trust, certificate signatures, validity dates, and CA constraints for TLS server authentication, with an additional check for CA certificate-signing key usage. These checks follow [RFC 5280 path validation](https://www.rfc-editor.org/rfc/rfc5280.html#section-6). The report shows the failure reason and separate hostname, certificate date, TLS handshake signature, and leaf revocation statuses. Only the supplied intermediates are used; cached intermediates and AIA downloads cannot hide an incomplete chain.

Remote checks download the leaf certificate's HTTP or HTTPS CRLs. CRL checks verify the issuer, scope, signature, signing key usage, and update dates. A revoked leaf reports `INVALID`. Missing, unavailable, expired, unsupported, or unauthenticated revocation data reports `UNKNOWN`. If the other checks pass but revocation is unknown, the overall status is also `UNKNOWN`. These checks cover leaf CRLs; they do not check OCSP or intermediate revocation.

CRL downloads use up to 5 seconds within the overall fetch timeout. Up to 8 URLs are tried, with a 10 MiB response limit per URL. CRL service failures do not prevent inspection or `--dump`.

System trust roots are used by default. Add custom trust roots from PEM files with `--ca-file`. Each file can contain multiple CA certificates, and the option can be repeated. Custom roots add to the system roots. Certificates supplied by the server do not become trusted roots.

```console
inspect-cert-chain --host <hostname> --ca-file <ca.pem>
inspect-cert-chain --host <hostname> --ca-file <ca.pem> --ca-file <other-ca.pem>
```

From chain file:

```console
inspect-cert-chain --file <path>
```

From stdin:

```console
cat <path> | inspect-cert-chain --file -
```

## Check mode

Use `--check` to check the validity dates of every certificate in the chain. It checks that the current time is between `not_before` and `not_after`, inclusive. Check mode exit codes reflect dates and expiry thresholds. Remote chains also show trust validation by default. For local trust validation, add `--hostname` as described below.

```console
inspect-cert-chain --host example.com --check
inspect-cert-chain --file chain.pem --check
```

Check mode uses these exit codes:

| Code | Status   | Meaning                                                                                                                     |
| ---- | -------- | --------------------------------------------------------------------------------------------------------------------------- |
| `0`  | OK       | All certificates are within their validity periods and outside the thresholds                                               |
| `1`  | Warning  | At least one certificate is within the warning threshold                                                                    |
| `2`  | Critical | At least one certificate has expired, is not yet valid, has an invalid validity period, or is within the critical threshold |
| `3`  | Unknown  | Invalid options, an empty chain, or a read, parse, fetch, or output error                                                   |

The exit code reflects the most severe result across the chain. Text check mode prints a status and reason for each certificate, then a chain summary.

Without `--check`, certificate dates do not change the exit code. Inspection errors exit with `1`, and invalid options exit with `3`. Invalid options print a usage error to stderr and leave stdout empty. `--help` and `--version` exit with `0`. Interactive mode cannot be combined with `--check`.

## Expiry thresholds

Use `--warn-within` and `--critical-within` to set expiry thresholds for check mode.

```console
inspect-cert-chain --host example.com --check --warn-within 30d --critical-within 7d
```

Both options require `--check`. Each option accepts a non-negative duration such as `30d`, `12h`, or `500ms`. A certificate at or inside a threshold gets that status. A critical result takes precedence over a warning. If you set both thresholds, the critical duration must not exceed the warning duration. No expiry threshold applies by default.

## Field selection

Use `--fields` to select certificate fields. You can use a comma-separated list or repeat the option. Text keeps the full OpenSSL-like output when you omit it. Field selection does not change the check result or omit the chain summary. Interactive mode cannot be combined with `--fields`.

```console
inspect-cert-chain --file chain.pem --fields subject,issuer,not_after
inspect-cert-chain --file chain.pem --check --fields subject,not_after,status
```

Text prints the fields in the requested order. It prints strings without quotes, and objects and arrays as compact JSON values.

| Field                 | Value                                                            |
| --------------------- | ---------------------------------------------------------------- |
| `subject`             | Distinguished name string                                        |
| `issuer`              | Distinguished name string                                        |
| `version`             | X.509 version number (`1`, `2`, or `3`)                          |
| `serial_number`       | Hex string                                                       |
| `signature_algorithm` | Object with `oid` and `name`                                     |
| `not_before`          | UTC date string, for example `2026-10-02T12:00:00Z`              |
| `not_after`           | UTC date string                                                  |
| `expires_in_seconds`  | Signed number of whole seconds until expiry                      |
| `subject_alt_names`   | Array of names, for example `DNS:example.com` or `IP:127.0.0.1`  |
| `public_key`          | Object with `algorithm` (`oid` and `name`) and hex `value`       |
| `extensions`          | Array of objects with `oid`, `name`, `critical`, and hex `value` |
| `signature`           | Hex string                                                       |
| `status`              | Object with `level` (`ok`, `warning`, `critical`) and `reason`   |

Hex strings use lowercase digits with no separators. Extension `value` contains the DER-encoded extension value. An absent subject alternate name extension gives an empty array. For expired certificates, `expires_in_seconds` is negative. The `status` field reports validity dates; it does not confirm certificate trust.

## JSON output

Use `--json` to write a JSON object with a `certificates` array. The array keeps the order from the host or input file. JSON includes all certificate fields from the table above when you omit `--fields`. Logs and error details go to stderr, including when you use `-v`. Interactive mode cannot be combined with `--json`.

```console
inspect-cert-chain --host example.com --json
inspect-cert-chain --file chain.pem --json --fields subject,not_after
inspect-cert-chain --file chain.pem --check --json --fields subject,not_after,status
```

For example, `--json --fields subject,not_after` returns:

```json
{
  "certificates": [
    {
      "subject": "CN=example.com",
      "not_after": "2026-12-31T23:59:59Z"
    }
  ]
}
```

With `--check`, JSON adds a top-level `"check": { "status": "ok" }` object. After options pass validation, a JSON input, fetch, or dump error returns an `error` string. Check mode also returns `"check": { "status": "unknown" }`. Invalid options leave stdout empty. JSON does not change the exit codes.

Remote JSON output and local checks with `--hostname` also include a top-level `validation` object. Its `status` is `valid`, `invalid`, or `unknown`. It includes separate `path`, `hostname`, `dates`, and leaf `revocation` results. Remote results include `handshake_signature`. Each result has a `status` and a `reason` when it fails or is unknown. The hostname result also includes the expected `name`. The `dates` array follows certificate order. Local revocation has status `not_checked` when no CRL is supplied. `--fields` selects certificate data and keeps the validation results.

## Local chain validation

Use `--check --hostname <name>` to show validation status for a local chain or stdin. The first certificate must be the server certificate. The remaining certificates supply the intermediates. The hostname can be a DNS name or an IP address.

```console
inspect-cert-chain --file <chain.pem> --check --hostname <hostname>
inspect-cert-chain --file <chain.pem> --check --hostname <hostname> --ca-file <ca.pem>
cat <chain.pem> | inspect-cert-chain --file - --check --hostname <hostname>
```

Use repeatable `--crl-file` options for offline leaf revocation checks with DER files or PEM bundles. Remote checks use these files instead of CRL downloads when the option is supplied. Local checks do not download CRLs; without `--crl-file`, local validation covers the path and hostname.

```console
inspect-cert-chain --file <chain.pem> --check --hostname <hostname> --ca-file <ca.pem> --crl-file <issuer.crl>
```

The date status is shown for each supplied certificate. A trust anchor is an input to path validation; its own expiry or self-signature is not a required path check. The existing date check and its exit codes still apply to every supplied certificate. Trust, hostname, signature, and revocation failures are displayed without changing these exit codes.

`just test` runs the CLI tests with generated chains and local TLS and CRL servers. `just test-badssl` runs the public badssl.com checks for expiry, hostname mismatch, missing trust, incomplete chains, and revocation, plus a valid control. The public checks require network access and are excluded from the normal test run.

# Remote smoke tests

Run `just test-remote` to inspect the hosts in `tests/fixtures/remote-hosts.txt`. This manual check requires internet access and reports all failures before it exits. Each host has a 30-second time limit. Use `just test-remote 10s` to change this limit. You can pass a different fixture as the second argument.

The CLI shows validation status and keeps invalid certificates available for inspection. The smoke tests must inspect expired certificates, self-signed certificates, and certificates for another hostname from [BadSSL](https://badssl.com/). Unsupported TLS versions, unsupported cipher suites, and oversized handshake messages must fail with the specified TLS error. DNS errors and timeouts do not count as expected TLS failures.

# Roadmap

- [x] OpenSSL-like text info.
- [x] Fetch certificate chain from remote host.
- [x] Read certificate chain from file and stdin.
- [x] Interpret standard X.509 extensions.
- [x] Option to read local chain files.
- [x] Determine chain validity.

[`homebrew`]: https://brew.sh
[`cargo-binstall`]: https://github.com/cargo-bins/cargo-binstall
