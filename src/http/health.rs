use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::storage::Storage;

#[derive(Clone)]
pub struct HealthState<S: Storage + Clone> {
    pub storage: Arc<S>,
    pub version: &'static str,
}

pub async fn health_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<HealthState<S>>,
) -> impl IntoResponse {
    let db_ok = state.storage.get_vendor_config().await.is_ok();
    let (status_code, db_str, status_str) = if db_ok {
        (StatusCode::OK, "ok", "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "error", "error")
    };
    (
        status_code,
        Json(json!({
            "status": status_str,
            "version": state.version,
            "database": db_str,
            "test_mode": false,
        })),
    )
}
