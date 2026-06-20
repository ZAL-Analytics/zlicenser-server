use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::auth::extract_session;
use super::state::DashboardState;
use super::util::format_ns_as_rfc3339;
use crate::storage::Storage;

pub async fn get_vendor_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
) -> Response {
    if extract_session(&headers, &state).await.is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }

    match state.storage.get_vendor_config().await {
        Ok(Some(config)) => {
            let key_hex = hex::encode(&config.public_key);
            Json(json!({
                "public_key_hex": key_hex,
                "public_key_fingerprint": config.public_key_fingerprint,
                "registered_at": format_ns_as_rfc3339(config.registered_at),
                "rotated_from_key": config.rotated_from_key.as_deref().map(hex::encode),
                "rotated_at": config.rotated_at.map(format_ns_as_rfc3339),
                "test_mode": state.test_mode,
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_configured","test_mode":state.test_mode})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}
