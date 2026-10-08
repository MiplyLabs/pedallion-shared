# pedallion-shared changelog

The licensing wire contract between the Pedallion client and the license server
(`pedallion-licensing`). Both pin a `vX.Y.Z` tag of this repo. Any change to a serialized field,
a signing context or an endpoint path is a contract change: add an entry here, bump `version` in
`Cargo.toml`, and tag `vX.Y.Z` on master (see `README.md`).

## [0.1.0] - 2026-10-08

Tag `v0.1.0`. Moved out of the `pedallion` repo, where the same contract was tagged
`shared-v0.1` (`pedallion` commit `73fc01a`); the code is unchanged.

First contract.

### Added
- Endpoints: `POST /v1/activate`, `POST /v1/heartbeat`, `GET /v1/version` (no query parameters).
- Types: `ActivateRequest {key, machine_fp, app_version, os}`, `ActivateResponse {lease}`,
  `HeartbeatRequest {license_id, machine_fp, app_version, os}`, `HeartbeatResponse {lease}`,
  `ErrorResponse {reason, message}`, `DenyReason` (`invalid_key`, `revoked`, `blocked`,
  `seats_exhausted`, `subscription_expired`, `version_unsupported`; unknown values decode as
  `unknown`), `VersionManifest {latest, min_supported, download_url, changelog_url, sha256}`,
  `MachineFingerprint` (SHA-256 hex).
- `Lease {license_id, machine_fp, issued_at, lease_expires_at, sub_expires_at, features, nonce}`
  with `time_status(now)` (5 minute clock skew).
- `Signed<T> {payload, signature}`: base64 of the exact signed JSON plus an Ed25519 signature,
  signed under a per-type context (`pedallion-lease-v1\0`, `pedallion-manifest-v1\0`), verified
  with `verify_strict`.
- `sign_lease` / `verify_lease` (also checks the machine binding), `sign_manifest` /
  `verify_manifest`, base64 key helpers, and `examples/keygen.rs`.
- Denials are a **403** with an `ErrorResponse` body; the client treats any other non-2xx as
  transient.
