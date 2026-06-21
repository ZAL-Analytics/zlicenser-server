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
    AuditAction, AuditTargetType, License, LicenseFilter, LicenseStatus, Page, RevocationRecord,
    RevocationSource, Storage,
};

fn license_to_json(l: &License, payment_sandbox: bool) -> Value {
    json!({
        "id": l.id,
        "customer_id": l.customer_id,
        "product_id": l.product_id,
        "bundle_version": l.bundle_version,
        "connectivity_mode": l.connectivity_mode.to_string(),
        "seat_count": l.seat_count,
        "expiry_at": l.expiry_at.map(format_ns_as_rfc3339),
        "status": l.status.to_string(),
        "superseded_by": l.superseded_by,
        "revoked_at": l.revoked_at.map(format_ns_as_rfc3339),
        "revocation_reason": l.revocation_reason,
        "created_at": format_ns_as_rfc3339(l.created_at),
        "email_sent_at": l.email_sent_at.map(format_ns_as_rfc3339),
        "payment_sandbox": payment_sandbox,
    })
}

#[allow(clippy::implicit_hasher)]
pub async fn list_licenses_handler<S: Storage + Clone + Send + Sync + 'static>(
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

    let filter = LicenseFilter {
        product_id: params.get("product_id").and_then(|s| s.parse().ok()),
        status: params.get("status").and_then(|s| s.parse().ok()),
        mode: params.get("mode").and_then(|s| s.parse().ok()),
        search: params.get("search").cloned(),
    };
    let page_num: u32 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1);
    let page_size: u32 = params
        .get("page_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let page = Page::new(page_num, page_size);

    match state.storage.list_licenses(&filter, page).await {
        Ok(paged) => {
            let items: Vec<Value> = paged
                .items
                .iter()
                .map(|l| license_to_json(l, state.payment_sandbox))
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

pub async fn get_license_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    if extract_session(&headers, &state).await.is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }
    match state.storage.get_license(id).await {
        Ok(Some(l)) => Json(license_to_json(&l, state.payment_sandbox)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct RevokeLicenseBody {
    pub reason: Option<String>,
}

pub async fn revoke_license_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RevokeLicenseBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let license = match state.storage.get_license(id).await {
        Ok(Some(l)) => l,
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

    if license.status != LicenseStatus::Active {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"license_not_active","status":license.status.to_string(),"payment_sandbox":state.payment_sandbox})),
        ).into_response();
    }

    let now = now_ns();
    if let Err(e) = state
        .storage
        .update_license_status(
            id,
            LicenseStatus::Revoked,
            Some(now),
            body.reason.as_deref(),
            None,
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    let record = RevocationRecord {
        license_id: id,
        revoked_at: now,
        revoked_by: RevocationSource::VendorDashboard,
        reason: body.reason.clone(),
    };
    let _ = state.storage.create_revocation_record(&record).await;

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::LicenseRevoke,
            AuditTargetType::License,
            Some(id),
            body.reason,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

#[derive(Deserialize)]
pub struct RevokeAllBody {
    pub reason: Option<String>,
}

pub async fn revoke_all_customer_licenses_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
    Json(body): Json<RevokeAllBody>,
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
        .get_customer(customer_id)
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

    let licenses = match state.storage.list_licenses_for_customer(customer_id).await {
        Ok(ls) => ls,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error","message":e.to_string()})),
            )
                .into_response();
        }
    };

    let now = now_ns();
    let mut revoked = 0u32;
    for license in licenses
        .iter()
        .filter(|l| l.status == LicenseStatus::Active)
    {
        if state
            .storage
            .update_license_status(
                license.id,
                LicenseStatus::Revoked,
                Some(now),
                body.reason.as_deref(),
                None,
            )
            .await
            .is_ok()
        {
            let record = RevocationRecord {
                license_id: license.id,
                revoked_at: now,
                revoked_by: RevocationSource::VendorDashboard,
                reason: body.reason.clone(),
            };
            let _ = state.storage.create_revocation_record(&record).await;
            revoked += 1;
        }
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::CustomerRevokeAll,
            AuditTargetType::Customer,
            Some(customer_id),
            Some(format!("revoked {revoked} licenses")),
        ),
    )
    .await;

    Json(json!({"ok":true,"revoked":revoked,"payment_sandbox":state.payment_sandbox}))
        .into_response()
}

pub async fn client_versions_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(product_id): Path<Uuid>,
) -> Response {
    if extract_session(&headers, &state).await.is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }

    match state
        .storage
        .count_active_licenses_per_client_version(product_id)
        .await
    {
        Ok(counts) => {
            let versions: Vec<Value> = counts
                .iter()
                .map(|(version, count)| json!({"version": version, "active_licenses": count}))
                .collect();
            Json(json!({"versions": versions, "payment_sandbox": state.payment_sandbox}))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn evidence_bundle_stub_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(_id): Path<Uuid>,
) -> Response {
    if extract_session(&headers, &state).await.is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "error": "not_implemented",
            "message": "Evidence bundle export is not yet implemented",
            "payment_sandbox": state.payment_sandbox,
        })),
    )
        .into_response()
}
