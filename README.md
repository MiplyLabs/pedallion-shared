# pedallion-shared

The licensing wire contract between the Pedallion desktop client (`MiplyLabs/pedallion`) and the
Pedallion licensing server (`MiplyLabs/pedallion-licensing`): request/response types, the lease
and version-manifest formats, and Ed25519 sign/verify.

It holds no keys and no secrets. The server keeps the signing key; the client is built with the
matching public key. Security doesn't depend on this code being private: a lease can only be
signed with the server's key.

Proprietary: published for use by Pedallion and for reading, not for reuse. See `LICENSE`.

## Requirements

- Rust 1.85+ (`cargo`)

## Installation

Both consumers depend on it by git tag:

```toml
pedallion-shared = { git = "https://github.com/MiplyLabs/pedallion-shared", tag = "v0.1.0" }
```

To work on the contract and a consumer at the same time, point the consumer at a local checkout
in its `Cargo.toml` (don't commit this):

```toml
[patch."https://github.com/MiplyLabs/pedallion-shared"]
pedallion-shared = { path = "../pedallion-shared" }
```

## Usage

```sh
cargo run --example keygen   # prints a new key pair: secret for the server, public for client builds
```

Never commit the secret half. It goes into the licensing server's secret store only.

## Releasing a contract change

Any change to a serialized field, a signing context or an endpoint path is a contract change.

1. Add the entry to `CHANGELOG.md` and bump `version` in `Cargo.toml`. Merge to `master`.
2. Run G4 on master's HEAD, then `git tag -a vX.Y.Z -m "pedallion-shared X.Y.Z"` and push the tag.
3. `notes="$(mktemp)" && scripts/release_notes.sh X.Y.Z > "$notes" && gh release create vX.Y.Z --title "pedallion-shared X.Y.Z" --notes-file "$notes"`.
4. Bump the tag in the client and the server.

## Testing

```sh
make fast       # fmt, clippy -D warnings, tests, staged secret scan (pre-commit gate)
make full       # fast + changed-line coverage >= 80%
make security   # cargo audit, semgrep, branch secret scan
```

The tests pin the exact JSON of every wire type. If one fails, the contract changed: release a
new version.
