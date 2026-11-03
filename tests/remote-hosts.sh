#!/usr/bin/env bash
set -euo pipefail

timeout="${1:-30s}"
fixture="${2:-tests/fixtures/remote-hosts.txt}"
output_dir="$(mktemp -d)"
trap 'rm -rf "$output_dir"' EXIT

passed=0
failed=0

while read -r expected host port error_pattern || [[ -n "$expected" ]]; do
    case "$expected" in
        ''|'#'*) continue ;;
        success) ;;
        failure)
            if [[ -z "$error_pattern" ]]; then
                printf 'Missing error pattern for %s:%s\n' "$host" "$port" >&2
                exit 1
            fi
            ;;
        *)
            printf 'Unknown fixture result: %s\n' "$expected" >&2
            exit 1
            ;;
    esac

    status=0

    cargo run --quiet --bin inspect-cert-chain -- \
        --host "$host" --port "$port" --timeout "$timeout" \
        >"$output_dir/stdout" 2>"$output_dir/stderr" || status=$?

    if [[ "$expected" == success && "$status" == 0 ]] \
        && rg -q '^Certificate$' "$output_dir/stdout"; then
        printf 'PASS %s:%s (certificate inspected)\n' "$host" "$port"
        passed=$((passed + 1))
    elif [[ "$expected" == failure && "$status" == 1 ]] \
        && [[ ! -s "$output_dir/stdout" ]] \
        && rg -q -- "$error_pattern" "$output_dir/stderr"; then
        printf 'PASS %s:%s (expected TLS failure)\n' "$host" "$port"
        passed=$((passed + 1))
    else
        printf 'FAIL %s:%s (expected %s, exit %s)\n' "$host" "$port" "$expected" "$status" >&2

        if [[ "$expected" == failure ]]; then
            printf 'Expected error pattern: %s\n' "$error_pattern" >&2
        fi

        cat "$output_dir/stderr" >&2
        failed=$((failed + 1))
    fi
done <"$fixture"

printf '\n%s passed; %s failed\n' "$passed" "$failed"
[[ "$passed" -gt 0 && "$failed" == 0 ]]
