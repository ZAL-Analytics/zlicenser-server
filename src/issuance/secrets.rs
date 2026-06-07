use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

const AT_REST_WRAP_INFO: &[u8] = b"zlicenser-server-s-issue-at-rest-v1";
const AIRGAP_WRAP_INFO: &[u8] = b"zlicenser-airgapped-s-issue-wrap-v1";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SIssue([u8; 32]);

impl SIssue {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn derive_at_rest_key(vendor_seed: &[u8; 32]) -> crate::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, vendor_seed);
    let mut okm = [0u8; 32];
    hk.expand(AT_REST_WRAP_INFO, &mut okm)
        .map_err(|e| crate::Error::SecretWrappingFailed(e.to_string()))?;
    Ok(okm)
}

pub fn encrypt_s_issue_at_rest(s_issue: &SIssue, at_rest_key: &[u8; 32]) -> crate::Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(at_rest_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, s_issue.as_bytes().as_ref())
        .map_err(|e| crate::Error::SecretWrappingFailed(e.to_string()))?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_s_issue_at_rest(ciphertext: &[u8], at_rest_key: &[u8; 32]) -> crate::Result<SIssue> {
    if ciphertext.len() < 12 {
        return Err(crate::Error::Corrupt("issuance secret too short".into()));
    }
    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(at_rest_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|_| crate::Error::Corrupt("issuance secret decryption failed".into()))?;

    let bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| crate::Error::Corrupt("issuance secret wrong length".into()))?;
    Ok(SIssue(bytes))
}

#[derive(Clone)]
pub struct WrappedSecret {
    pub ephemeral_pubkey: [u8; 32],
    pub ciphertext: Vec<u8>,
}

pub fn wrap_s_issue_for_airgap(
    s_issue: &SIssue,
    customer_ed25519_pubkey: &[u8; 32],
) -> crate::Result<WrappedSecret> {
    let vk = VerifyingKey::from_bytes(customer_ed25519_pubkey)
        .map_err(|e| crate::Error::SecretWrappingFailed(e.to_string()))?;
    let customer_x25519_bytes: [u8; 32] = vk.to_montgomery().to_bytes();
    let customer_x25519 = PublicKey::from(customer_x25519_bytes);

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_pubkey = PublicKey::from(&ephemeral_secret);

    let shared_secret = ephemeral_secret.diffie_hellman(&customer_x25519);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(AIRGAP_WRAP_INFO, &mut wrap_key)
        .map_err(|e| crate::Error::SecretWrappingFailed(e.to_string()))?;

    let key = Key::<Aes256Gcm>::from_slice(&wrap_key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, s_issue.as_bytes().as_ref())
        .map_err(|e| crate::Error::SecretWrappingFailed(e.to_string()))?;

    let mut ciphertext = Vec::with_capacity(12 + ct.len());
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&ct);

    wrap_key.zeroize();

    Ok(WrappedSecret {
        ephemeral_pubkey: *ephemeral_pubkey.as_bytes(),
        ciphertext,
    })
}
