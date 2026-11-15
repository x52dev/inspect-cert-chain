_list:
    @just --list

# Lint workspace.
clippy:
    cargo clippy --workspace --no-default-features
    cargo clippy --workspace --all-features
    cargo hack --feature-powerset --depth=3 clippy --workspace

# Lint workspace and watch for changes.
clippy-watch:
    cargo watch -- cargo clippy --workspace --all-features

# Apply possible linting fixes in the workspace.
clippy-fix *args:
    cargo clippy --workspace --all-features --fix {{ args }}
    cargo +nightly fmt

# Test workspace.
test:
    cargo nextest run --workspace --all-features --no-tests=pass

# Check remote host fixtures (requires internet access).
test-remote timeout="30s" fixture="tests/fixtures/remote-hosts.txt":
    cargo build --bin inspect-cert-chain
    bash tests/remote-hosts.sh "{{ timeout }}" "{{ fixture }}"

# Check public badssl.com certificate failures. Requires network access.
test-badssl:
    cargo nextest run --workspace --all-features --run-ignored ignored-only -E 'binary(badssl)'

# Document workspace.
doc *args:
    RUSTDOCFLAGS="--cfg=docsrs" cargo +nightly doc --no-deps --workspace --all-features {{ args }}

# Document workspace and watch for changes.
doc-watch: (doc "--open")
    cargo watch -- RUSTDOCFLAGS="--cfg=docsrs" cargo +nightly doc --no-deps --workspace --all-features

# Check project formatting.
check:
    just --unstable --fmt --check
    nixpkgs-fmt .
    fd --hidden --extension=md --extension=yml --exec-batch prettier --check
    fd --hidden --extension=toml --exec-batch taplo format --check
    fd --hidden --extension=toml --exec-batch taplo lint
    cargo +nightly fmt -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Format project.
fmt:
    just --unstable --fmt
    nixpkgs-fmt .
    fd --hidden --extension=md --extension=yml --exec-batch prettier --write
    fd --hidden --extension=toml --exec-batch taplo format
    cargo +nightly fmt
