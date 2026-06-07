use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::issuance::handlers::HandlerContext;
use crate::storage::Storage;

pub async fn stripe_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let secret = match ctx.config.stripe_webhook_secret.as_deref() {
        Some(s) => s,
        None => return StatusCode::NOT_IMPLEMENTED.into_response(),
    };

    let sig_header = match headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing stripe-signature").into_response(),
    };

    if !verify_stripe_signature(sig_header, &body, secret) {
        return (StatusCode::UNAUTHORIZED, "invalid stripe-signature").into_response();
    }

    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };

    let event_type = event["type"].as_str().unwrap_or("");
    if event_type == "payment_intent.payment_failed" {
        let intent_id = event["data"]["object"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !intent_id.is_empty() {
            let storage = ctx.storage.clone();
            tokio::spawn(async move {
                if let Ok(Some(session)) = storage.get_session_by_payment_intent(&intent_id).await {
                    crate::issuance::handlers::abandon(
                        &storage,
                        session.id,
                        crate::storage::types::abandon_reason::PAYMENT_FAILED,
                    )
                    .await;
                }
            });
        }
    }

    StatusCode::OK.into_response()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let inner: [u8; 32] = Sha256::new()
        .chain_update(ipad)
        .chain_update(data)
        .finalize()
        .into();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn verify_stripe_signature(header: &str, body: &[u8], secret: &str) -> bool {
    let mut timestamp = None;
    let mut signature_hex: Option<&str> = None;

    for part in header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature_hex = Some(v);
        }
    }

    let (ts, sig_hex) = match (timestamp, signature_hex) {
        (Some(t), Some(s)) => (t, s),
        _ => return false,
    };

    let expected_bytes = match hex_to_bytes(sig_hex) {
        Some(b) => b,
        None => return false,
    };

    let signed_payload = format!("{}.{}", ts, String::from_utf8_lossy(body));
    let computed = hmac_sha256(secret.as_bytes(), signed_payload.as_bytes());

    computed.as_ref() == expected_bytes.as_slice()
}
