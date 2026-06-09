use std::sync::Arc;

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zlicenser_protocol::sessions::{SessionRequest, SessionResponse};

use crate::{
    issuance::handlers::HandlerContext,
    storage::{ActiveSession, ConnectivityMode, LicenseStatus, SessionStatus, Storage},
};

use super::crypto;

/// 24-hour session TTL in nanoseconds.
const SESSION_TTL_NS: i64 = 86_400 * 1_000_000_000;

pub(crate) async fn establish_session<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    req: SessionRequest,
    now_ns: i64,
) -> crate::Result<SessionResponse> {
    // Validate binding, any mismatch returns BindingNotFound to avoid enumeration.
    let binding = ctx
        .storage
        .get_seat_binding(req.binding_id)
        .await?
        .filter(|b| b.license_id == req.license_id && b.revoked_at.is_none())
        .ok_or(crate::Error::BindingNotFound)?;

    let license = ctx
        .storage
        .get_license(req.license_id)
        .await?
        .filter(|l| l.status == LicenseStatus::Active)
        .ok_or(crate::Error::BindingNotFound)?;

    let product = ctx
        .storage
        .get_product(license.product_id)
        .await?
        .ok_or(crate::Error::BindingNotFound)?;

    if product.connectivity_mode != ConnectivityMode::AlwaysOnline {
        return Err(crate::Error::BindingNotFound);
    }
    if !product.active {
        return Err(crate::Error::ProductInactive);
    }

    // Reject if any live session already exists for this binding.
    if ctx
        .storage
        .get_active_or_suspect_session_for_binding(req.binding_id)
        .await?
        .is_some()
    {
        return Err(crate::Error::MultipleSessionsRejected);
    }

    // Validate the client's ephemeral X25519 public key.
    let client_pk_bytes: [u8; 32] = req
        .ephemeral_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| crate::Error::BindingNotFound)?;

    // Server-side ECDH: generate ephemeral keypair, derive shared secret.
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pubkey = X25519PublicKey::from(&server_secret);
    let shared = server_secret.diffie_hellman(&X25519PublicKey::from(client_pk_bytes));

    let session_id = Uuid::new_v4();

    // HKDF-SHA256 to derive a 256-bit wrapping key for the session material.
    let hk = Hkdf::<Sha256>::new(Some(b"zlicenser-session-material-v1"), shared.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(session_id.as_bytes(), &mut wrap_key)
        .expect("32 bytes is a valid HKDF output length");

    // Encrypt the HMAC key for the shim (session_material payload).
    let hmac_key = crypto::generate_session_hmac_key();
    let wrap_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
    let mut mat_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut mat_nonce);
    let mat_ct = wrap_cipher
        .encrypt(Nonce::from_slice(&mat_nonce), hmac_key.as_ref())
        .map_err(|_| crate::Error::Corrupt("session material encryption failed".into()))?;

    // session_material = server_pubkey(32) || nonce(12) || ciphertext+tag(48) = 92 bytes
    let mut session_material = Vec::with_capacity(92);
    session_material.extend_from_slice(server_pubkey.as_bytes());
    session_material.extend_from_slice(&mat_nonce);
    session_material.extend_from_slice(&mat_ct);

    // Session parameters, fall back to safe defaults when the product config is absent.
    let heartbeat_interval_secs =
        u32::try_from(product.heartbeat_interval_secs.unwrap_or(30)).unwrap_or(30);
    let heartbeat_grace_secs =
        u32::try_from(product.heartbeat_grace_secs.unwrap_or(10)).unwrap_or(10);
    let shutdown_countdown_secs =
        u32::try_from(product.shutdown_countdown_secs.unwrap_or(60)).unwrap_or(60);

    let session_token = crypto::generate_session_token();
    let session_hmac_key_encrypted = crypto::encrypt_hmac_key(&hmac_key, &ctx.at_rest_key)?;
    let expires_at_ns = now_ns + SESSION_TTL_NS;

    ctx.storage
        .create_session(&ActiveSession {
            id: session_id,
            binding_id: binding.id,
            license_id: req.license_id,
            product_id: product.id,
            session_token,
            session_hmac_key_encrypted,
            heartbeat_interval_secs,
            heartbeat_grace_secs,
            shutdown_countdown_secs,
            seq_no: 0,
            last_heartbeat_at: None,
            expires_at: expires_at_ns,
            status: SessionStatus::Active,
            command_pending: None,
            created_at: now_ns,
            updated_at: now_ns,
        })
        .await?;

    Ok(SessionResponse {
        session_id,
        session_material,
        seq_no: 0,
        session_token,
        expires_at: expires_at_ns / 1_000_000_000,
        heartbeat_interval_secs,
        heartbeat_grace_secs,
        shutdown_countdown_secs,
    })
}
