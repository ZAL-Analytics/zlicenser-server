use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use zlicenser_protocol::sessions::SecurityEventReport;

use crate::issuance::handlers::{HandlerContext, now_ns};
use crate::storage::Storage;

pub async fn security_event_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    Json(report): Json<SecurityEventReport>,
) -> Response {
    match crate::sessions::security::handle_security_event(&ctx, report, now_ns()).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}
