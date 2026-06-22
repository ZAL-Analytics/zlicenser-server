use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::http::extract::{JsonBody, PathParam};
use crate::issuance::handlers::HandlerContext;
use crate::storage::{Storage, types::RevocationSource};

#[derive(Deserialize)]
pub struct RevokeBody {
    pub reason: Option<String>,
}

pub async fn revoke_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<RevokeBody>,
) -> Response {
    if let Some(expected) = &ctx.config.api_bearer_token {
        use secrecy::ExposeSecret as _;
        use subtle::ConstantTimeEq as _;
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !bool::from(
            provided
                .as_bytes()
                .ct_eq(expected.expose_secret().as_bytes()),
        ) {
            return (StatusCode::UNAUTHORIZED, "invalid bearer token").into_response();
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
