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
use crate::storage::{
    ActiveSessionUpdate, AuditAction, AuditTargetType, Page, PendingCommand, QuarantineCase,
    QuarantineTrigger, SecurityEventFilter, SecurityEventRecord, SessionStatus, Storage,
};

fn event_to_json(e: &SecurityEventRecord, payment_sandbox: bool) -> Value {
    json!({
        "id": e.id,
        "event_id": e.event_id,
        "license_id": e.license_id,
        "binding_id": e.binding_id,
        "session_id": e.session_id,
        "occurred_at": format_ns_as_rfc3339(e.occurred_at_ns),
        "received_at": format_ns_as_rfc3339(e.received_at_ns),
        "event_type": e.event_type,
        "payload": e.payload,
        "severity": e.severity,
        "response_type": e.response_type,
        "case_id": e.case_id,
        "reviewed_at": e.reviewed_at.map(format_ns_as_rfc3339),
        "false_positive_at": e.false_positive_at.map(format_ns_as_rfc3339),
        "payment_sandbox": payment_sandbox,
    })
}

#[allow(clippy::implicit_hasher)]
pub async fn list_security_events_handler<S: Storage + Clone + Send + Sync + 'static>(
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

    let filter = SecurityEventFilter {
        license_id: params.get("license_id").and_then(|s| s.parse().ok()),
        binding_id: params.get("binding_id").and_then(|s| s.parse().ok()),
        product_id: params.get("product_id").and_then(|s| s.parse().ok()),
    };
    let page_num: u32 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1);
    let page_size: u32 = params
        .get("page_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let page = Page::new(page_num, page_size);

    match state.storage.list_security_events(&filter, page).await {
        Ok(paged) => {
            let items: Vec<Value> = paged
                .items
                .iter()
                .map(|e| event_to_json(e, state.payment_sandbox))
                .collect();
            Json(json!({
                "items": items,
                "total": paged.total,
                "page": paged.page,
                "page_size": paged.page_size,
                "payment_sandbox": state.payment_sandbox,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn review_security_event_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let now = now_ns();
    if let Err(e) = state.storage.mark_security_event_reviewed(id, now).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::SecurityEventReview,
            AuditTargetType::SecurityEvent,
            None,
            Some(id.to_string()),
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

pub async fn false_positive_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let now = now_ns();
    if let Err(e) = state
        .storage
        .mark_security_event_false_positive(id, now)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::SecurityEventFalsePositive,
            AuditTargetType::SecurityEvent,
            None,
            Some(id.to_string()),
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

#[derive(Deserialize)]
pub struct QuarantineBody {
    pub reason: String,
}

pub async fn quarantine_binding_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(binding_id): Path<Uuid>,
    Json(body): Json<QuarantineBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    if state
        .storage
        .get_seat_binding(binding_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let active_session = match state
        .storage
        .get_active_or_suspect_session_for_binding(binding_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"no_active_session","payment_sandbox":state.payment_sandbox})),
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

    let now = now_ns();
    let case = QuarantineCase {
        id: Uuid::new_v4(),
        case_id: Uuid::new_v4(),
        binding_id,
        session_id: Some(active_session.id),
        trigger: QuarantineTrigger::VendorAction,
        trigger_event_id: None,
        reason: body.reason,
        created_at: now,
        resumed_at: None,
    };

    if let Err(e) = state.storage.create_quarantine_case(&case).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    let update = ActiveSessionUpdate {
        status: Some(SessionStatus::Quarantined),
        command_pending: None,
        updated_at: now,
        ..Default::default()
    };
    let _ = state
        .storage
        .update_active_session(active_session.id, active_session.updated_at, update)
        .await;

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::BindingQuarantine,
            AuditTargetType::Binding,
            Some(binding_id),
            None,
        ),
    )
    .await;

    Json(json!({"ok":true,"case_id":case.case_id,"payment_sandbox":state.payment_sandbox}))
        .into_response()
}

pub async fn terminate_binding_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(binding_id): Path<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    if state
        .storage
        .get_seat_binding(binding_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let active_session = match state
        .storage
        .get_active_or_suspect_session_for_binding(binding_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"no_active_session","payment_sandbox":state.payment_sandbox})),
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

    let now = now_ns();
    let update = ActiveSessionUpdate {
        command_pending: Some(Some(PendingCommand::Terminate)),
        updated_at: now,
        ..Default::default()
    };
    if let Err(e) = state
        .storage
        .update_active_session(active_session.id, active_session.updated_at, update)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::BindingTerminate,
            AuditTargetType::Binding,
            Some(binding_id),
            None,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

pub async fn resume_binding_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(binding_id): Path<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    if state
        .storage
        .get_seat_binding(binding_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let qcase = match state
        .storage
        .get_active_quarantine_case_for_binding(binding_id)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(
                    json!({"error":"no_active_quarantine","payment_sandbox":state.payment_sandbox}),
                ),
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

    let now = now_ns();
    if let Err(e) = state.storage.resume_quarantine_case(qcase.id, now).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    if let Some(session_id) = qcase.session_id
        && let Ok(Some(active)) = state.storage.get_session(session_id).await
    {
        let update = ActiveSessionUpdate {
            command_pending: Some(Some(PendingCommand::Resume)),
            updated_at: now,
            ..Default::default()
        };
        let _ = state
            .storage
            .update_active_session(active.id, active.updated_at, update)
            .await;
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::BindingResume,
            AuditTargetType::Binding,
            Some(binding_id),
            None,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}
