//! Pedallion licensing contract, shared by the desktop client (this repo) and the licensing
//! server (`pedallion-licensing`, which pins a `shared-vX.Y` tag of this crate).
//!
//! Everything here is plain data plus Ed25519 sign/verify: no I/O, no clocks. Times are unix
//! seconds passed in by the caller. The server holds the signing key; the client embeds only
//! the verifying key, so it can check leases and version manifests but never mint them.
//!
//! Signed values travel as [`Signed<T>`]: the payload is the exact JSON bytes that were signed
//! (base64), so neither side has to agree on a canonical JSON form. Each payload type signs
//! under its own context prefix, so a signed manifest can never pass as a lease or vice versa.
//!
//! Changing any serialized field is a contract change: bump the crate version and tag it.

use std::fmt;
use std::marker::PhantomData;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Server endpoints, relative to the licensing server's base URL.
pub const ACTIVATE_PATH: &str = "/v1/activate";
pub const HEARTBEAT_PATH: &str = "/v1/heartbeat";
pub const VERSION_PATH: &str = "/v1/version";

/// Stable per-machine identifier: a SHA-256 hex digest of machine-specific inputs. The client
/// decides which inputs; the server only stores and compares the digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MachineFingerprint(pub String);

impl MachineFingerprint {
    /// Hash `components` (in order) into a fingerprint. Components are NUL-separated so
    /// `["ab", "c"]` and `["a", "bc"]` differ.
    pub fn from_components(components: &[&str]) -> Self {
        let mut h = Sha256::new();
        h.update(b"pedallion-fp-v1");
        for c in components {
            h.update([0u8]);
            h.update(c.as_bytes());
        }
        Self(hex(&h.finalize()))
    }
}

impl fmt::Display for MachineFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A server-issued grant for one license on one machine. `lease_expires_at` is the end of the
/// offline grace window; `sub_expires_at` is the end of the paid subscription. The client must
/// honour both, whichever comes first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub license_id: String,
    pub machine_fp: MachineFingerprint,
    pub issued_at: i64,
    pub lease_expires_at: i64,
    pub sub_expires_at: i64,
    pub features: Vec<String>,
    /// Random per-issue value so two leases are never byte-identical.
    pub nonce: String,
}

/// How a lease stands at a given instant. Signature and machine binding are checked by
/// [`verify_lease`]; this is only the time dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseTime {
    Valid,
    /// Offline grace ran out. A heartbeat may renew it.
    LeaseExpired,
    /// The subscription itself ended. Only the server can extend it.
    SubscriptionExpired,
    /// `now` is before the lease was issued: the clock was wound back.
    BeforeIssue,
}

/// Leeway for small clock differences between server and client.
pub const CLOCK_SKEW_SECS: i64 = 5 * 60;

impl Lease {
    pub fn time_status(&self, now: i64) -> LeaseTime {
        if now + CLOCK_SKEW_SECS < self.issued_at {
            LeaseTime::BeforeIssue
        } else if now >= self.sub_expires_at {
            LeaseTime::SubscriptionExpired
        } else if now >= self.lease_expires_at {
            LeaseTime::LeaseExpired
        } else {
            LeaseTime::Valid
        }
    }
}

/// Signed release metadata served at [`VERSION_PATH`]. The client trusts `download_url` only
/// after [`verify_manifest`] succeeds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionManifest {
    /// Semver of the newest release.
    pub latest: String,
    /// Oldest semver the server still accepts in heartbeats.
    pub min_supported: String,
    pub download_url: String,
    pub changelog_url: String,
    /// SHA-256 hex of the artifact at `download_url`.
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateRequest {
    pub key: String,
    pub machine_fp: MachineFingerprint,
    pub app_version: String,
    pub os: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateResponse {
    pub lease: SignedLease,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub license_id: String,
    pub machine_fp: MachineFingerprint,
    pub app_version: String,
    pub os: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub lease: SignedLease,
}

/// Why the server refused an activate or heartbeat. Sent as the body of a **403**: the client
/// treats only 403 + this body as a denial (which drops its cached lease); any other non-2xx is
/// a transient error that keeps the offline grace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    InvalidKey,
    Revoked,
    Blocked,
    SeatsExhausted,
    SubscriptionExpired,
    VersionUnsupported,
    /// A reason added to the server after this client was built.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub reason: DenyReason,
    pub message: String,
}

/// A payload type that can be signed. `CONTEXT` is prepended to the bytes before signing so
/// signatures don't transfer between types.
pub trait SignedPayload: Serialize + DeserializeOwned {
    const CONTEXT: &'static [u8];
}

impl SignedPayload for Lease {
    const CONTEXT: &'static [u8] = b"pedallion-lease-v1\0";
}

impl SignedPayload for VersionManifest {
    const CONTEXT: &'static [u8] = b"pedallion-manifest-v1\0";
}

/// A payload plus its Ed25519 signature, both base64. `payload` is the signed JSON verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Signed<T> {
    pub payload: String,
    pub signature: String,
    #[serde(skip)]
    _type: PhantomData<fn() -> T>,
}

pub type SignedLease = Signed<Lease>;
pub type SignedManifest = Signed<VersionManifest>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractError {
    /// Not valid base64, wrong length, or not a valid key/signature encoding.
    Encoding,
    /// The signature does not match the payload under this key.
    BadSignature,
    /// Signature is fine but the payload JSON doesn't parse as the expected type.
    Payload,
    /// A valid lease for a different machine.
    WrongMachine,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encoding => "malformed key or signature encoding",
            Self::BadSignature => "signature verification failed",
            Self::Payload => "signed payload is not the expected type",
            Self::WrongMachine => "lease is bound to a different machine",
        })
    }
}

impl std::error::Error for ContractError {}

fn message<T: SignedPayload>(payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(T::CONTEXT.len() + payload.len());
    m.extend_from_slice(T::CONTEXT);
    m.extend_from_slice(payload);
    m
}

/// Sign `value`. Server-side only: the signing key never ships in the client.
pub fn sign<T: SignedPayload>(value: &T, key: &SigningKey) -> Signed<T> {
    let payload = serde_json::to_vec(value).expect("contract types always serialize");
    let signature = key.sign(&message::<T>(&payload));
    Signed {
        payload: B64.encode(&payload),
        signature: B64.encode(signature.to_bytes()),
        _type: PhantomData,
    }
}

/// Check the signature and decode the payload. Uses strict verification (rejects weak keys
/// and malleable signatures).
pub fn verify<T: SignedPayload>(
    signed: &Signed<T>,
    key: &VerifyingKey,
) -> Result<T, ContractError> {
    let payload = B64
        .decode(&signed.payload)
        .map_err(|_| ContractError::Encoding)?;
    let sig_bytes = B64
        .decode(&signed.signature)
        .map_err(|_| ContractError::Encoding)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| ContractError::Encoding)?;
    key.verify_strict(&message::<T>(&payload), &signature)
        .map_err(|_| ContractError::BadSignature)?;
    serde_json::from_slice(&payload).map_err(|_| ContractError::Payload)
}

pub fn sign_lease(lease: &Lease, key: &SigningKey) -> SignedLease {
    sign(lease, key)
}

/// Verify a lease's signature and that it is bound to `machine`. Expiry is separate
/// ([`Lease::time_status`]) because an authentic but expired lease still tells the client
/// which license to heartbeat for.
pub fn verify_lease(
    signed: &SignedLease,
    key: &VerifyingKey,
    machine: &MachineFingerprint,
) -> Result<Lease, ContractError> {
    let lease = verify(signed, key)?;
    if &lease.machine_fp != machine {
        return Err(ContractError::WrongMachine);
    }
    Ok(lease)
}

pub fn sign_manifest(manifest: &VersionManifest, key: &SigningKey) -> SignedManifest {
    sign(manifest, key)
}

pub fn verify_manifest(
    signed: &SignedManifest,
    key: &VerifyingKey,
) -> Result<VersionManifest, ContractError> {
    verify(signed, key)
}

/// Parse a base64 Ed25519 public key (32 bytes), the form the client embeds.
pub fn verifying_key_from_base64(s: &str) -> Result<VerifyingKey, ContractError> {
    let bytes: [u8; 32] = B64
        .decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(ContractError::Encoding)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ContractError::Encoding)
}

/// Parse a base64 Ed25519 secret key (32 bytes), the form the server loads from its secret.
pub fn signing_key_from_base64(s: &str) -> Result<SigningKey, ContractError> {
    let bytes: [u8; 32] = B64
        .decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(ContractError::Encoding)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn verifying_key_to_base64(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn fp(s: &str) -> MachineFingerprint {
        MachineFingerprint::from_components(&[s])
    }

    fn lease() -> Lease {
        Lease {
            license_id: "lic_123".into(),
            machine_fp: fp("machine-a"),
            issued_at: 1_000,
            lease_expires_at: 1_000 + 48 * 3600,
            sub_expires_at: 1_000 + 30 * 86_400,
            features: vec!["pro".into()],
            nonce: "n1".into(),
        }
    }

    fn manifest() -> VersionManifest {
        VersionManifest {
            latest: "0.2.0".into(),
            min_supported: "0.1.0".into(),
            download_url: "https://example.com/pedallion-0.2.0.dmg".into(),
            changelog_url: "https://example.com/changelog".into(),
            sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn lease_round_trips() {
        let k = key(1);
        let signed = sign_lease(&lease(), &k);
        let got = verify_lease(&signed, &k.verifying_key(), &fp("machine-a")).unwrap();
        assert_eq!(got, lease());
    }

    #[test]
    fn lease_rejects_wrong_key() {
        let signed = sign_lease(&lease(), &key(1));
        let err = verify_lease(&signed, &key(2).verifying_key(), &fp("machine-a"));
        assert_eq!(err, Err(ContractError::BadSignature));
    }

    #[test]
    fn lease_rejects_tampered_payload() {
        let k = key(1);
        let mut signed = sign_lease(&lease(), &k);
        let mut forged = lease();
        forged.sub_expires_at += 365 * 86_400;
        signed.payload = B64.encode(serde_json::to_vec(&forged).unwrap());
        let err = verify_lease(&signed, &k.verifying_key(), &fp("machine-a"));
        assert_eq!(err, Err(ContractError::BadSignature));
    }

    #[test]
    fn lease_rejects_other_machine() {
        let k = key(1);
        let signed = sign_lease(&lease(), &k);
        let err = verify_lease(&signed, &k.verifying_key(), &fp("machine-b"));
        assert_eq!(err, Err(ContractError::WrongMachine));
    }

    #[test]
    fn garbage_encoding_is_an_encoding_error() {
        let k = key(1);
        let mut signed = sign_lease(&lease(), &k);
        signed.signature = "not base64!".into();
        let err = verify_lease(&signed, &k.verifying_key(), &fp("machine-a"));
        assert_eq!(err, Err(ContractError::Encoding));
        signed.signature = B64.encode([0u8; 10]);
        let err = verify_lease(&signed, &k.verifying_key(), &fp("machine-a"));
        assert_eq!(err, Err(ContractError::Encoding));
    }

    #[test]
    fn manifest_round_trips_and_rejects_bad_signature() {
        let k = key(1);
        let signed = sign_manifest(&manifest(), &k);
        assert_eq!(verify_manifest(&signed, &k.verifying_key()), Ok(manifest()));
        assert_eq!(
            verify_manifest(&signed, &key(9).verifying_key()),
            Err(ContractError::BadSignature)
        );
        let mut evil = signed.clone();
        let mut m = manifest();
        m.download_url = "https://evil.example/malware.dmg".into();
        evil.payload = B64.encode(serde_json::to_vec(&m).unwrap());
        assert_eq!(
            verify_manifest(&evil, &k.verifying_key()),
            Err(ContractError::BadSignature)
        );
    }

    #[test]
    fn signature_does_not_transfer_between_types() {
        // Same key, same bytes, different context: a lease signature can't validate a manifest.
        let k = key(1);
        let signed = sign_lease(&lease(), &k);
        let as_manifest: SignedManifest = Signed {
            payload: signed.payload,
            signature: signed.signature,
            _type: PhantomData,
        };
        assert_eq!(
            verify_manifest(&as_manifest, &k.verifying_key()),
            Err(ContractError::BadSignature)
        );
    }

    #[test]
    fn lease_time_status() {
        let l = lease();
        assert_eq!(l.time_status(l.issued_at), LeaseTime::Valid);
        assert_eq!(l.time_status(l.lease_expires_at - 1), LeaseTime::Valid);
        assert_eq!(l.time_status(l.lease_expires_at), LeaseTime::LeaseExpired);
        assert_eq!(
            l.time_status(l.sub_expires_at),
            LeaseTime::SubscriptionExpired
        );
        // Small skew is tolerated, a real rollback is not.
        assert_eq!(l.time_status(l.issued_at - 60), LeaseTime::Valid);
        assert_eq!(
            l.time_status(l.issued_at - CLOCK_SKEW_SECS - 1),
            LeaseTime::BeforeIssue
        );
    }

    #[test]
    fn subscription_end_wins_over_fresh_lease() {
        let mut l = lease();
        l.sub_expires_at = l.issued_at + 3600;
        assert_eq!(
            l.time_status(l.issued_at + 3600),
            LeaseTime::SubscriptionExpired
        );
    }

    #[test]
    fn fingerprint_is_stable_and_separated() {
        assert_eq!(fp("a"), fp("a"));
        assert_ne!(fp("a"), fp("b"));
        assert_ne!(
            MachineFingerprint::from_components(&["ab", "c"]),
            MachineFingerprint::from_components(&["a", "bc"])
        );
        assert_eq!(fp("a").0.len(), 64);
    }

    #[test]
    fn key_base64_round_trip() {
        let k = key(3);
        let b64 = verifying_key_to_base64(&k.verifying_key());
        assert_eq!(verifying_key_from_base64(&b64).unwrap(), k.verifying_key());
        assert_eq!(
            signing_key_from_base64(&B64.encode([3u8; 32]))
                .unwrap()
                .verifying_key(),
            k.verifying_key()
        );
        assert_eq!(
            verifying_key_from_base64("AAAA"),
            Err(ContractError::Encoding)
        );
    }

    // The wire format is the contract with the server. These pin it: if one fails, you
    // changed the contract and need a new `shared-vX.Y` tag.

    #[test]
    fn lease_wire_format() {
        assert_eq!(
            serde_json::to_string(&lease()).unwrap(),
            format!(
                r#"{{"license_id":"lic_123","machine_fp":"{}","issued_at":1000,"lease_expires_at":173800,"sub_expires_at":2593000,"features":["pro"],"nonce":"n1"}}"#,
                fp("machine-a")
            )
        );
    }

    #[test]
    fn dto_wire_format() {
        let req = ActivateRequest {
            key: "K".into(),
            machine_fp: MachineFingerprint("f".into()),
            app_version: "0.1.0".into(),
            os: "macos".into(),
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"key":"K","machine_fp":"f","app_version":"0.1.0","os":"macos"}"#
        );
        let hb = HeartbeatRequest {
            license_id: "L".into(),
            machine_fp: MachineFingerprint("f".into()),
            app_version: "0.1.0".into(),
            os: "linux".into(),
        };
        assert_eq!(
            serde_json::to_string(&hb).unwrap(),
            r#"{"license_id":"L","machine_fp":"f","app_version":"0.1.0","os":"linux"}"#
        );
        let signed: SignedLease = Signed {
            payload: "p".into(),
            signature: "s".into(),
            _type: PhantomData,
        };
        assert_eq!(
            serde_json::to_string(&ActivateResponse {
                lease: signed.clone()
            })
            .unwrap(),
            r#"{"lease":{"payload":"p","signature":"s"}}"#
        );
        assert_eq!(
            serde_json::to_string(&manifest()).unwrap(),
            format!(
                r#"{{"latest":"0.2.0","min_supported":"0.1.0","download_url":"https://example.com/pedallion-0.2.0.dmg","changelog_url":"https://example.com/changelog","sha256":"{}"}}"#,
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn deny_reason_wire_format_and_forward_compat() {
        let e: ErrorResponse =
            serde_json::from_str(r#"{"reason":"seats_exhausted","message":"full"}"#).unwrap();
        assert_eq!(e.reason, DenyReason::SeatsExhausted);
        let e: ErrorResponse =
            serde_json::from_str(r#"{"reason":"something_new","message":"?"}"#).unwrap();
        assert_eq!(e.reason, DenyReason::Unknown);
        assert_eq!(
            serde_json::to_string(&DenyReason::VersionUnsupported).unwrap(),
            r#""version_unsupported""#
        );
    }
}
