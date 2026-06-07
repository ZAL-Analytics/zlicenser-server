use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::issuance::handlers::HandlerContext;
use crate::storage::{Storage, types::RevocationSource};

#[derive(Deserialize)]
pub struct RevokeBody {
    pub reason: Option<String>,
}

pub async fn revoke_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RevokeBody>,
) -> Response {
    if let Some(expected_token) = ctx.config.api_bearer_token.as_deref() {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match auth {
            Some(token) if token == expected_token => {}
            _ => {
                return (StatusCode::UNAUTHORIZED, "invalid bearer token").into_response();
            }
        }
    }

    match crate::issuance::revoke::revoke_license(
        &ctx.storage,
        id,
        body.reason,
        RevocationSource::Api,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}
