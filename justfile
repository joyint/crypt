# Crypt -- Task Runner
#
# joy-crypt is the leaf crypto crate (ADR-039). It publishes to crates.io
# ahead of joy so joy-core resolves against a fresh joy-crypt, exactly as
# joy-core publishes ahead of joy-cli within the joy workspace. The
# umbrella lists `crypt` first in `subs` for this reason.

# List recipes
default:
    @just --list

# Run all tests
test:
    cargo test --workspace

# Format all code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Lint all code
lint:
    cargo clippy --workspace -- -D warnings

# Abort if the local Rust stable toolchain is behind the latest release.
[private]
_toolchain-check:
    #!/usr/bin/env bash
    if rustup check stable 2>/dev/null | grep -q "Update available"; then
        echo "Error: Rust stable toolchain is outdated. Run 'rustup update stable'."
        exit 1
    fi

# Run fmt-check, lint, test
check: _toolchain-check fmt-check lint test

# Auto-commit known generated files (.joy/, lockfiles)
[private]
auto-commit:
    #!/usr/bin/env bash
    files=(.joy/ Cargo.lock)
    staged=false
    for f in "${files[@]}"; do
        if git status --porcelain "$f" 2>/dev/null | grep -q .; then
            git add "$f"
            staged=true
        fi
    done
    if [ "$staged" = true ]; then
        git commit --quiet -m "chore: update generated files [no-item]"
        echo "Committed pending changes."
    fi

# Release (bump: patch, minor, or major)
release bump="patch":
    #!/usr/bin/env bash
    set -euo pipefail
    if git describe --tags --exact-match HEAD >/dev/null 2>&1; then
        echo "No changes since last tag, skipping."
        exit 0
    fi
    just auto-commit
    if ! command -v joy >/dev/null 2>&1 || ! [ -f ".joy/project.yaml" ]; then
        echo "No Joy project found. Use joy init to set up."
        exit 1
    fi
    if ! joy release show >/dev/null 2>&1; then
        echo "No items closed since last release."
        exit 0
    fi
    # Joy logs every invocation to .joy/logs/YYYY-MM-DD.log, so the
    # `joy release show` above may have dirtied the tree. Absorb those
    # writes before the clean check, otherwise the release aborts on
    # its own audit trail.
    just auto-commit
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: working tree is not clean."
        exit 1
    fi
    echo "Updating external dependencies..."
    cargo update
    just auto-commit
    echo "Bumping version files..."
    joy release bump "{{bump}}"
    echo "Refreshing Cargo.lock..."
    cargo update --workspace
    echo "Checking (format, lint, test)..."
    if ! just check > /dev/null 2>&1; then
        echo "Checks failed. Run 'just check' for details. Rolling bump back."
        git restore crates/ Cargo.lock
        exit 1
    fi
    joy release record "{{bump}}"
    tag=$(git describe --tags --exact-match HEAD 2>/dev/null || echo "unknown")
    echo "Tagged ${tag} locally. Run 'just publish' to ship."

# Upload crates to crates.io only. Idempotent: already-uploaded
# versions are skipped. The forge release is handled separately by
# `joy release publish`.
publish-crates:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
        echo "Error: CARGO_REGISTRY_TOKEN is not set."
        echo "  - Local: add it to the umbrella's .env (see .env.example)."
        echo "  - CI: export it from the runner's secret store."
        exit 1
    fi
    # Order matters: joy-token depends on joy-crypt.
    crates=(joy-crypt joy-token)
    for crate in "${crates[@]}"; do
        version=$(cargo pkgid --quiet -p "$crate" 2>/dev/null | sed 's/.*[#@]\(.*\)/\1/')
        if [ -z "$version" ]; then
            echo "Warning: could not resolve version for $crate, skipping."
            continue
        fi
        # cargo search lags the registry by minutes, so we also catch
        # "already uploaded" from the actual publish call below.
        if cargo search "$crate" --limit 1 2>/dev/null | grep -qE "^$crate = \"$version\""; then
            echo "$crate $version already on crates.io, skipping."
            continue
        fi
        echo "Publishing $crate $version..."
        if ! out=$(cargo publish -p "$crate" 2>&1); then
            # Two cargo error variants both mean "version already published":
            # - "is already uploaded": registry rejected the upload
            # - "already exists on crates.io index": cargo's pre-check
            if echo "$out" | grep -qE "is already uploaded|already exists on crates.io index"; then
                echo "$crate $version already on crates.io (registry confirmed), skipping."
            else
                echo "$out" >&2
                exit 1
            fi
        else
            echo "$out"
        fi
        sleep 5
    done
    echo "crates.io uploads complete."

# Full publish: upload crates + push + create forge release. Called
# per sub by `just release-all` in the umbrella. crates.io upload runs
# first so a failed upload leaves only a local tag to drop.
publish: publish-crates
    joy release publish
