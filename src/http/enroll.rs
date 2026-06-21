use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use uuid::Uuid;

use crate::http::extract::{JsonBody, PathParam};
use crate::issuance::handlers::{ConsentInput, HandlerContext, LicenseReceipt, LicenseRequest};
use crate::storage::Storage;

pub async fn request_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    JsonBody(req): JsonBody<LicenseRequest>,
) -> Response {
    match crate::issuance::handlers::handle_license_request(&ctx, req).await {
        Ok(offer) => (StatusCode::OK, Json(offer)).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct ReceiptBody {
    pub offer_nonce: Vec<u8>,
    pub customer_signature: Vec<u8>,
    pub consent: ConsentInput,
}

pub async fn receipt_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    PathParam(session_id): PathParam<Uuid>,
    JsonBody(body): JsonBody<ReceiptBody>,
) -> Response {
    let customer_signature: [u8; 64] = match body.customer_signature.try_into() {
        Ok(sig) => sig,
        Err(_) => return crate::Error::InvalidReceiptSignature.into_response(),
    };
    let receipt = LicenseReceipt {
        offer_nonce: body.offer_nonce,
        customer_signature,
        consent: body.consent,
    };
    match crate::issuance::handlers::handle_license_receipt(&ctx, session_id, receipt).await {
        Ok(grant) => {
            #[derive(Serialize)]
            struct GrantResponse {
                license_id: String,
                binding_cert_bytes: Vec<u8>,
                tsa_token: Vec<u8>,
                wrapped_ephemeral_pubkey: Option<Vec<u8>>,
                wrapped_ciphertext: Option<Vec<u8>>,
            }
            (
                StatusCode::OK,
                Json(GrantResponse {
                    license_id: grant.license_id.to_string(),
                    binding_cert_bytes: grant.binding_cert.to_bytes(),
                    tsa_token: grant.tsa_token,
                    wrapped_ephemeral_pubkey: grant
                        .wrapped_secret
                        .as_ref()
                        .map(|w| w.ephemeral_pubkey.to_vec()),
                    wrapped_ciphertext: grant.wrapped_secret.map(|w| w.ciphertext),
                }),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}
