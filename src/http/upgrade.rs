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
pub struct UpgradeBody {
    pub to_bundle_version: String,
}

pub async fn upgrade_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    Path(license_id): Path<Uuid>,
    Json(body): Json<UpgradeBody>,
) -> Response {
    match crate::issuance::upgrade::handle_upgrade_activation(
        &ctx.storage,
        license_id,
        &body.to_bundle_version,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}
