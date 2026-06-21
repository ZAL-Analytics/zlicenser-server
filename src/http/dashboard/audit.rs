use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use uuid::Uuid;

use super::auth::extract_session;
use super::state::DashboardState;
use super::util::{format_ns_as_rfc3339, parse_iso_ns};
use crate::storage::{AuditEntry, AuditFilter, Page, Storage};

fn audit_entry_to_json(e: &AuditEntry) -> serde_json::Value {
    json!({
        "id": e.id,
        "occurred_at": format_ns_as_rfc3339(e.occurred_at),
        "auth_method": e.auth_method.to_string(),
        "action": e.action.to_string(),
        "target_type": e.target_type.to_string(),
        "target_id": e.target_id,
        "detail": e.detail,
    })
}

#[allow(clippy::implicit_hasher)]
pub async fn list_audit_log_handler<S: Storage + Clone + Send + Sync + 'static>(
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

    let action = params.get("action").and_then(|s| s.parse().ok());
    let target_id = params.get("target_id").and_then(|s| s.parse::<Uuid>().ok());
    let from_ns = params.get("from").and_then(|s| parse_iso_ns(s));
    let to_ns = params.get("to").and_then(|s| parse_iso_ns(s));
    let page_num: u32 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1);
    let page_size: u32 = params
        .get("page_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let filter = AuditFilter {
        action,
        target_id,
        from_ns,
        to_ns,
    };
    let page = Page::new(page_num, page_size);

    match state.storage.list_audit_entries(&filter, page).await {
        Ok(paged) => {
            let items: Vec<serde_json::Value> =
                paged.items.iter().map(audit_entry_to_json).collect();
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
