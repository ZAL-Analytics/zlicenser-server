pub mod dashboard;
pub mod enroll;
pub mod health;
pub mod middleware;
pub mod product_info;
pub mod revoke;
pub mod security;
pub mod sessions;
pub mod transfer;
pub mod upgrade;
pub mod webhook;

use std::sync::Arc;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, post},
};
use serde_json::json;

use crate::issuance::handlers::HandlerContext;
use crate::storage::Storage;

pub fn build_router<S: Storage + Clone + Send + Sync + 'static>(
    ctx: Arc<HandlerContext<S>>,
) -> Router {
    Router::new()
        .route("/enroll/request", post(enroll::request_handler::<S>))
        .route(
            "/enroll/receipt/{session_id}",
            post(enroll::receipt_handler::<S>),
        )
        .route("/webhook/stripe", post(webhook::stripe_handler::<S>))
        .route("/licenses/{id}", delete(revoke::revoke_handler::<S>))
        .route(
            "/licenses/{id}/transfer/request",
            post(transfer::request_handler::<S>),
        )
        .route(
            "/transfers/{id}/approve",
            post(transfer::approve_handler::<S>),
        )
        .route(
            "/transfers/{id}/reject",
            post(transfer::reject_handler::<S>),
        )
        .route(
            "/licenses/{id}/upgrade",
            post(upgrade::upgrade_handler::<S>),
        )
        .route(
            "/sessions/establish",
            post(sessions::establish_handler::<S>),
        )
        .route(
            "/sessions/{session_id}/heartbeat",
            post(sessions::heartbeat_handler::<S>),
        )
        .route(
            "/security/events",
            post(security::security_event_handler::<S>),
        )
        .with_state(ctx)
}

impl IntoResponse for crate::Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            crate::Error::NotFound
            | crate::Error::SessionNotFound
            | crate::Error::BindingNotFound
            | crate::Error::ActiveSessionNotFound => (StatusCode::NOT_FOUND, "not_found"),

            crate::Error::OfferExpired => (StatusCode::GONE, "offer_expired"),

            crate::Error::SessionExpired | crate::Error::SessionTerminated => {
                (StatusCode::GONE, "session_gone")
            }

            crate::Error::SessionTokenMismatch
            | crate::Error::HeartbeatHmacFailed
            | crate::Error::Unauthorized
            | crate::Error::DashboardAuthFailed => (StatusCode::UNAUTHORIZED, "unauthorized"),

            crate::Error::DashboardPasswordNotConfigured => {
                (StatusCode::FORBIDDEN, "not_configured")
            }

            crate::Error::MultipleSessionsRejected
            | crate::Error::SeatLimitReached
            | crate::Error::Conflict(_)
            | crate::Error::TransferAlreadyPending
            | crate::Error::LicenseHasBeenIssued => (StatusCode::CONFLICT, "conflict"),

            crate::Error::InvalidTransition(_) => (StatusCode::CONFLICT, "invalid_transition"),

            crate::Error::PaymentNotHeld => (StatusCode::PAYMENT_REQUIRED, "payment_not_held"),

            crate::Error::TsaFailed(_) | crate::Error::PaymentCaptureFailed(_) => {
                (StatusCode::BAD_GATEWAY, "upstream_failure")
            }

            crate::Error::HeartbeatSequenceGap { .. }
            | crate::Error::ClientVersionRejected { .. }
            | crate::Error::OfferNonceMismatch
            | crate::Error::InvalidReceiptSignature
            | crate::Error::ConsentInvalid(_) => (StatusCode::BAD_REQUEST, "bad_request"),

            crate::Error::ProductInactive
            | crate::Error::RevocationNotSupported
            | crate::Error::ForeignKeyViolation(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "rejected")
            }

            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let body = Json(json!({ "error": code, "message": self.to_string() }));
        (status, body).into_response()
    }
}
