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

# Remote smoke tests

Run `just test-remote` to inspect the hosts in `tests/fixtures/remote-hosts.txt`. This manual check requires internet access and reports all failures before it exits. Each host has a 30-second time limit. Use `just test-remote 10s` to change this limit. You can pass a different fixture as the second argument.

The CLI does not validate certificates. It must inspect expired certificates, self-signed certificates, and certificates for another hostname from [BadSSL](https://badssl.com/). Unsupported TLS versions, unsupported cipher suites, and oversized handshake messages must fail with the specified TLS error. DNS errors and timeouts do not count as expected TLS failures.

# Roadmap

- [x] OpenSSL-like text info.
- [x] Fetch certificate chain from remote host.
- [x] Read certificate chain from file and stdin.
- [x] Interpret standard X.509 extensions.
- [x] Option to read local chain files.
- [ ] Determine chain validity.

[`homebrew`]: https://brew.sh
[`cargo-binstall`]: https://github.com/cargo-bins/cargo-binstall
