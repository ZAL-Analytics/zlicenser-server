use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use uuid::Uuid;
use zlicenser_protocol::sessions::{Heartbeat, SessionRequest};

use crate::http::extract::{JsonBody, PathParam};
use crate::issuance::handlers::{HandlerContext, now_ns};
use crate::storage::Storage;

pub async fn establish_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    JsonBody(req): JsonBody<SessionRequest>,
) -> Response {
    match crate::sessions::establish::establish_session(&ctx, req, now_ns()).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn heartbeat_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(ctx): State<Arc<HandlerContext<S>>>,
    PathParam(session_id): PathParam<Uuid>,
    JsonBody(hb): JsonBody<Heartbeat>,
) -> Response {
    if hb.session_id != session_id {
        return crate::Error::ActiveSessionNotFound.into_response();
    }
    match crate::sessions::heartbeat::handle_heartbeat(&ctx, hb, now_ns()).await {
        Ok(ack) => (StatusCode::OK, Json(ack)).into_response(),
        Err(e) => e.into_response(),
    }
}
