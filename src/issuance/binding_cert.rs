use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

use crate::storage::types::ConnectivityMode;

#[derive(Clone)]
pub struct BindingCert {
    pub license_id: Uuid,
    pub product_id: Uuid,
    pub fingerprint_commitment: [u8; 32],
    pub customer_pubkey: [u8; 32],
    pub seat_index: u32,
    pub issued_at_ns: i64,
    pub expiry_at_ns: Option<i64>,
    pub connectivity_mode: ConnectivityMode,
    pub vendor_sig: [u8; 64],
}

impl BindingCert {
    pub fn signing_input(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"zlicenser-binding-cert-v1\n");
        buf.extend_from_slice(self.license_id.as_bytes());
        buf.extend_from_slice(self.product_id.as_bytes());
        buf.extend_from_slice(&self.fingerprint_commitment);
        buf.extend_from_slice(&self.customer_pubkey);
        buf.extend_from_slice(&self.seat_index.to_be_bytes());
        buf.extend_from_slice(&self.issued_at_ns.to_be_bytes());
        match self.expiry_at_ns {
            Some(t) => {
                buf.push(1);
                buf.extend_from_slice(&t.to_be_bytes());
            }
            None => {
                buf.push(0);
            }
        }
        buf.extend_from_slice(self.connectivity_mode.to_string().as_bytes());
        buf
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        let sig: Signature = signing_key.sign(&self.signing_input());
        self.vendor_sig = sig.to_bytes();
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> crate::Result<()> {
        let sig = Signature::from_bytes(&self.vendor_sig);
        verifying_key
            .verify(&self.signing_input(), &sig)
            .map_err(|_| crate::Error::Corrupt("binding cert signature invalid".into()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.signing_input();
        buf.extend_from_slice(&self.vendor_sig);
        buf
    }
}
