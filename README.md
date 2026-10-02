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

From remote host:

```console
inspect-cert-chain --host <hostname>
```

Remote fetching has a `10s` overall timeout. Use `--timeout <DURATION>` to change it, for example `500ms`, `30s`, or `2m`. The duration must be greater than zero.

From chain file:

```console
inspect-cert-chain --file <path>
```

From stdin:

```console
cat <path> | inspect-cert-chain --file -
```

## Check mode

Use `--check` to check the validity dates of every certificate in the chain. It checks that the current time is between `not_before` and `not_after`, inclusive. It does not verify signatures, hostname matches, trust roots, or revocation.

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

# Roadmap

- [x] OpenSSL-like text info.
- [x] Fetch certificate chain from remote host.
- [x] Read certificate chain from file and stdin.
- [x] Interpret standard X.509 extensions.
- [x] Option to read local chain files.
- [ ] Determine chain validity.

[`homebrew`]: https://brew.sh
[`cargo-binstall`]: https://github.com/cargo-bins/cargo-binstall
