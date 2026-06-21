use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::auth::extract_session;
use super::state::DashboardState;
use super::util::{append_audit, format_ns_as_rfc3339, new_audit_entry, now_ns};
use crate::storage::{AuditAction, AuditTargetType, Storage, TransferRequest, TransferStatus};

fn transfer_to_json(r: &TransferRequest, payment_sandbox: bool) -> Value {
    json!({
        "id": r.id,
        "license_id": r.license_id,
        "old_fingerprint_commitment": hex::encode(&r.old_fingerprint_commitment),
        "new_fingerprint_commitment": hex::encode(&r.new_fingerprint_commitment),
        "requested_at": format_ns_as_rfc3339(r.requested_at),
        "status": r.status.to_string(),
        "vendor_note": r.vendor_note,
        "resolved_at": r.resolved_at.map(format_ns_as_rfc3339),
        "payment_sandbox": payment_sandbox,
    })
}

#[allow(clippy::implicit_hasher)]
pub async fn list_transfers_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    if extract_session(&headers, &state).await.is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }

    let product_id = params.get("product_id").and_then(|s| s.parse().ok());

    match state
        .storage
        .list_pending_transfer_requests(product_id)
        .await
    {
        Ok(requests) => {
            let items: Vec<Value> = requests
                .iter()
                .map(|r| transfer_to_json(r, state.payment_sandbox))
                .collect();
            Json(json!({"items": items, "payment_sandbox": state.payment_sandbox})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ResolveTransferBody {
    pub vendor_note: Option<String>,
}

pub async fn approve_transfer_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveTransferBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let request = match state.storage.get_transfer_request(id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error","message":e.to_string()})),
            )
                .into_response();
        }
    };

    if request.status != TransferStatus::Pending {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"already_resolved","status":request.status.to_string(),"payment_sandbox":state.payment_sandbox})),
        ).into_response();
    }

    let now = now_ns();
    if let Err(e) = state
        .storage
        .resolve_transfer_request(
            id,
            TransferStatus::Approved,
            body.vendor_note.as_deref(),
            now,
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    if let Ok(Some(binding)) = state
        .storage
        .find_seat_binding_by_commitment(request.license_id, &request.old_fingerprint_commitment)
        .await
    {
        let _ = state
            .storage
            .set_seat_binding_transfer_pending(binding.id, None)
            .await;
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::TransferApprove,
            AuditTargetType::Transfer,
            Some(id),
            body.vendor_note,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

pub async fn reject_transfer_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveTransferBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let request = match state.storage.get_transfer_request(id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error","message":e.to_string()})),
            )
                .into_response();
        }
    };

    if request.status != TransferStatus::Pending {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"already_resolved","status":request.status.to_string(),"payment_sandbox":state.payment_sandbox})),
        ).into_response();
    }

    let now = now_ns();
    if let Err(e) = state
        .storage
        .resolve_transfer_request(
            id,
            TransferStatus::Rejected,
            body.vendor_note.as_deref(),
            now,
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    if let Ok(Some(binding)) = state
        .storage
        .find_seat_binding_by_commitment(request.license_id, &request.old_fingerprint_commitment)
        .await
    {
        let _ = state
            .storage
            .set_seat_binding_transfer_pending(binding.id, None)
            .await;
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::TransferReject,
            AuditTargetType::Transfer,
            Some(id),
            body.vendor_note,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}
