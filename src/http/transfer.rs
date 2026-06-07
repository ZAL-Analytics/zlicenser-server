use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::issuance::handlers::HandlerContext;
use crate::storage::Storage;

#[derive(Deserialize)]
pub struct TransferRequestBody {
    pub old_fingerprint_commitment: Vec<u8>,
    pub new_fingerprint_commitment: Vec<u8>,
}

pub async fn request_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    Path(license_id): Path<Uuid>,
    Json(body): Json<TransferRequestBody>,
) -> Response {
    match crate::issuance::transfer::request_transfer(
        &ctx.storage,
        license_id,
        body.old_fingerprint_commitment,
        body.new_fingerprint_commitment,
    )
    .await
    {
        Ok(req) => (StatusCode::CREATED, Json(req.id.to_string())).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct ResolveBody {
    pub vendor_note: Option<String>,
}

pub async fn approve_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    Path(transfer_id): Path<Uuid>,
    Json(body): Json<ResolveBody>,
) -> Response {
    match crate::issuance::transfer::approve_transfer(&ctx.storage, transfer_id, body.vendor_note)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn reject_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    Path(transfer_id): Path<Uuid>,
    Json(body): Json<ResolveBody>,
) -> Response {
    match crate::issuance::transfer::reject_transfer(&ctx.storage, transfer_id, body.vendor_note)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}
