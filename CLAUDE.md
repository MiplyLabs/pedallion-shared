# pedallion-shared
Licensing wire contract shared by the Pedallion client and license server. Public, proprietary.

## Commands
- `make quick` (fmt, clippy, tests) · `make fast` (+ staged secret scan) · `make full` (+ coverage) · `make security` (audit, semgrep, branch secret scan)
- `cargo run --example keygen` prints a key pair
- `scripts/release_notes.sh X.Y.Z` prints a version's CHANGELOG section

## Layout
- `src/lib.rs` — every type, path and sign/verify function, plus tests that pin the JSON
- `examples/keygen.rs` — key pair generator
- `scripts/release_notes.sh` — CHANGELOG section → release notes

## Conventions and gotchas
- Any serialized-field, signing-context or path change is a contract change: CHANGELOG entry, `Cargo.toml` version bump, `vX.Y.Z` tag, then bump the tag in `pedallion` and `pedallion-licensing` (`README.md`).
- The repo is public: never commit keys or keygen output (`.gitignore` blocks the usual names).
- No I/O, no clock: callers pass `now` in unix seconds.

## Docs
- `README.md` (usage, releasing) · `CHANGELOG.md` · decisions live in `pedallion`'s `docs/decisions.md` (ADR-009, ADR-013)
