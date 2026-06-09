use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub(crate) const CMD_QUARANTINE: u8 = 0x01;
pub(crate) const CMD_TERMINATE: u8 = 0x02;

pub(crate) fn generate_session_token() -> [u8; 32] {
    let mut t = [0u8; 32];
    OsRng.fill_bytes(&mut t);
    t
}

pub(crate) fn generate_session_hmac_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// Encrypts a 32-byte HMAC key under `at_rest_key` using AES-256-GCM.
/// Output layout: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
pub(crate) fn encrypt_hmac_key(key: &[u8; 32], at_rest_key: &[u8; 32]) -> crate::Result<[u8; 60]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(at_rest_key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, key.as_ref())
        .map_err(|_| crate::Error::Corrupt("hmac key encryption failed".into()))?;
    // ct = 32 bytes plaintext + 16 bytes tag = 48 bytes
    let mut out = [0u8; 60];
    out[..12].copy_from_slice(&nonce_bytes);
    out[12..].copy_from_slice(&ct);
    Ok(out)
}

/// Decrypts a 60-byte encrypted HMAC key, returning the original 32-byte key.
pub(crate) fn decrypt_hmac_key(
    encrypted: &[u8; 60],
    at_rest_key: &[u8; 32],
) -> crate::Result<[u8; 32]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(at_rest_key));
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let plain = cipher
        .decrypt(nonce, &encrypted[12..])
        .map_err(|_| crate::Error::Corrupt("hmac key decryption failed".into()))?;
    plain
        .try_into()
        .map_err(|_| crate::Error::Corrupt("decrypted hmac key has wrong length".into()))
}

// HMAC input: session_id 16 bytes || seq_no 8 LE || session_token 32 bytes || fingerprint_commitment
pub(crate) fn compute_heartbeat_hmac(
    key: &[u8; 32],
    session_id: Uuid,
    seq_no: u64,
    session_token: &[u8; 32],
    fingerprint_commitment: &[u8],
) -> [u8; 32] {
    // HMAC accepts any key length; the expect is on a programmer invariant.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(session_id.as_bytes());
    mac.update(&seq_no.to_le_bytes());
    mac.update(session_token);
    mac.update(fingerprint_commitment);
    mac.finalize().into_bytes().into()
}

pub(crate) fn verify_heartbeat_hmac(
    key: &[u8; 32],
    session_id: Uuid,
    seq_no: u64,
    session_token: &[u8; 32],
    fingerprint_commitment: &[u8],
    provided: &[u8; 32],
) -> bool {
    let expected = compute_heartbeat_hmac(
        key,
        session_id,
        seq_no,
        session_token,
        fingerprint_commitment,
    );
    expected.ct_eq(provided).into()
}

/// Constant-time rolling token comparison.
pub(crate) fn verify_session_token(stored: &[u8; 32], provided: &[u8; 32]) -> bool {
    stored.ct_eq(provided).into()
}

// Canonical bytes: case_id 16 bytes || command_type 1 byte || seq_no 8 LE || reason_len 4 LE || reason UTF-8
pub(crate) fn canonical_command_bytes(
    case_id: Uuid,
    command_type: u8,
    seq_no: u64,
    reason: &str,
) -> Vec<u8> {
    let reason_bytes = reason.as_bytes();
    let mut out = Vec::with_capacity(16 + 1 + 8 + 4 + reason_bytes.len());
    out.extend_from_slice(case_id.as_bytes());
    out.push(command_type);
    out.extend_from_slice(&seq_no.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(reason_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(reason_bytes);
    out
}

pub(crate) fn sign_command(signing_key: &SigningKey, canonical: &[u8]) -> [u8; 64] {
    signing_key.sign(canonical).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_session_hmac_key();
        let at_rest_key = [0xABu8; 32];
        let enc = encrypt_hmac_key(&key, &at_rest_key).unwrap();
        let dec = decrypt_hmac_key(&enc, &at_rest_key).unwrap();
        assert_eq!(key, dec);
    }

    #[test]
    fn encrypt_decrypt_wrong_key_fails() {
        let key = generate_session_hmac_key();
        let enc = encrypt_hmac_key(&key, &[0xABu8; 32]).unwrap();
        assert!(decrypt_hmac_key(&enc, &[0xCDu8; 32]).is_err());
    }

    #[test]
    fn heartbeat_hmac_verify() {
        let key = generate_session_hmac_key();
        let sid = Uuid::new_v4();
        let token = generate_session_token();
        let fc = b"commitment-bytes";
        let mac = compute_heartbeat_hmac(&key, sid, 1, &token, fc);
        assert!(verify_heartbeat_hmac(&key, sid, 1, &token, fc, &mac));
        assert!(!verify_heartbeat_hmac(&key, sid, 2, &token, fc, &mac));
    }

    #[test]
    fn token_verify_constant_time() {
        let a = generate_session_token();
        let b = generate_session_token();
        assert!(verify_session_token(&a, &a));
        assert!(!verify_session_token(&a, &b));
    }

    #[test]
    fn canonical_command_bytes_layout() {
        let case_id = Uuid::nil();
        let reason = "test";
        let bytes = canonical_command_bytes(case_id, CMD_QUARANTINE, 7u64, reason);
        assert_eq!(bytes.len(), 16 + 1 + 8 + 4 + 4);
        assert_eq!(bytes[16], CMD_QUARANTINE);
        assert_eq!(&bytes[17..25], &7u64.to_le_bytes());
        assert_eq!(&bytes[25..29], &(4u32).to_le_bytes());
        assert_eq!(&bytes[29..], b"test");
    }
}
