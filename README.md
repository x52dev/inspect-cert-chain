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

| Code | Status   | Meaning                                                                                |
| ---- | -------- | -------------------------------------------------------------------------------------- |
| `0`  | OK       | All certificates are within their validity periods                                     |
| `2`  | Critical | At least one certificate has expired, is not yet valid, has an invalid validity period |
| `3`  | Unknown  | Invalid options, an empty chain, or a read, parse, fetch, or output error              |

The exit code reflects the most severe result across the chain. Text check mode prints a status and reason for each certificate, then a chain summary.

Without `--check`, certificate dates do not change the exit code. Inspection errors exit with `1`, and invalid options exit with `3`. Invalid options print a usage error to stderr and leave stdout empty. `--help` and `--version` exit with `0`. Interactive mode cannot be combined with `--check`.

# Roadmap

- [x] OpenSSL-like text info.
- [x] Fetch certificate chain from remote host.
- [x] Read certificate chain from file and stdin.
- [x] Interpret standard X.509 extensions.
- [x] Option to read local chain files.
- [ ] Determine chain validity.

[`homebrew`]: https://brew.sh
[`cargo-binstall`]: https://github.com/cargo-bins/cargo-binstall
