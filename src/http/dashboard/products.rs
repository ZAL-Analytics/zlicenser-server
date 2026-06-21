use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::auth::extract_session;
use super::state::DashboardState;
use super::util::{append_audit, new_audit_entry, now_ns};
use crate::storage::{
    AuditAction, AuditTargetType, ConnectivityMode, PaymentProvider, Product, Storage,
    TransferPolicy, TsaTier,
};

fn product_to_json(p: &Product, payment_sandbox: bool) -> Value {
    json!({
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "connectivity_mode": p.connectivity_mode.to_string(),
        "seat_count": p.seat_count,
        "expiry_policy": p.expiry_policy,
        "grace_period_days": p.grace_period_days,
        "heartbeat_interval_secs": p.heartbeat_interval_secs,
        "heartbeat_grace_secs": p.heartbeat_grace_secs,
        "shutdown_countdown_secs": p.shutdown_countdown_secs,
        "auto_quarantine_on_critical": p.auto_quarantine_on_critical,
        "tsa_tier": p.tsa_tier.to_string(),
        "bundle_version": p.bundle_version,
        "transfer_policy": p.transfer_policy.to_string(),
        "pricing_amount": p.pricing_amount,
        "pricing_currency": p.pricing_currency,
        "payment_provider": p.payment_provider.to_string(),
        "min_client_version_warning": p.min_client_version_warning,
        "min_client_version_required": p.min_client_version_required,
        "active": p.active,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "payment_sandbox": payment_sandbox,
    })
}

pub async fn list_products_handler<S: Storage + Clone + Send + Sync + 'static>(
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
    match state.storage.list_products().await {
        Ok(products) => {
            let items: Vec<Value> = products
                .iter()
                .map(|p| product_to_json(p, state.payment_sandbox))
                .collect();
            Json(json!({"products": items, "payment_sandbox": state.payment_sandbox}))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize, Serialize)]
pub struct CreateProductBody {
    pub name: String,
    pub description: Option<String>,
    pub connectivity_mode: String,
    pub seat_count: Option<i64>,
    pub expiry_policy: Option<String>,
    pub tsa_tier: Option<String>,
    pub bundle_version: Option<String>,
    pub transfer_policy: Option<String>,
    pub pricing_amount: Option<i64>,
    pub pricing_currency: Option<String>,
    pub payment_provider: Option<String>,
}

pub async fn create_product_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Json(body): Json<CreateProductBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let Ok(connectivity_mode) = body.connectivity_mode.parse::<ConnectivityMode>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"bad_request","message":"invalid connectivity_mode","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    };

    let tsa_tier = body
        .tsa_tier
        .as_deref()
        .unwrap_or("Free")
        .parse::<TsaTier>()
        .unwrap_or(TsaTier::Free);

    let transfer_policy = body
        .transfer_policy
        .as_deref()
        .unwrap_or("NotAvailable")
        .parse::<TransferPolicy>()
        .unwrap_or(TransferPolicy::NotAvailable);

    let payment_provider = body
        .payment_provider
        .as_deref()
        .unwrap_or("Stripe")
        .parse::<PaymentProvider>()
        .unwrap_or(PaymentProvider::Stripe);

    let now = now_ns();
    let product = Product {
        id: Uuid::new_v4(),
        name: body.name,
        description: body.description.unwrap_or_default(),
        connectivity_mode,
        seat_count: body.seat_count.unwrap_or(1),
        expiry_policy: body.expiry_policy.unwrap_or_else(|| "never".to_owned()),
        grace_period_days: None,
        heartbeat_interval_secs: None,
        heartbeat_grace_secs: None,
        shutdown_countdown_secs: None,
        auto_quarantine_on_critical: false,
        tsa_tier,
        bundle_version: body.bundle_version.unwrap_or_else(|| "0.1.0".to_owned()),
        transfer_policy,
        pricing_amount: body.pricing_amount.unwrap_or(0),
        pricing_currency: body.pricing_currency.unwrap_or_else(|| "USD".to_owned()),
        payment_provider,
        min_client_version_warning: None,
        min_client_version_required: None,
        active: false,
        created_at: now,
        updated_at: now,
    };

    if let Err(e) = state.storage.create_product(&product).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    let product_id = product.id;
    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::ProductCreate,
            AuditTargetType::Product,
            Some(product_id),
            None,
        ),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(product_to_json(&product, state.payment_sandbox)),
    )
        .into_response()
}

pub async fn get_product_handler<S: Storage + Clone + Send + Sync + 'static>(
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
    match state.storage.get_product(id).await {
        Ok(Some(p)) => Json(product_to_json(&p, state.payment_sandbox)).into_response(),
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
pub struct UpdateProductBody {
    pub name: Option<String>,
    pub description: Option<String>,
    pub seat_count: Option<i64>,
    pub expiry_policy: Option<String>,
    pub grace_period_days: Option<i64>,
    pub heartbeat_interval_secs: Option<i64>,
    pub heartbeat_grace_secs: Option<i64>,
    pub shutdown_countdown_secs: Option<i64>,
    pub auto_quarantine_on_critical: Option<bool>,
    pub bundle_version: Option<String>,
    pub min_client_version_warning: Option<String>,
    pub min_client_version_required: Option<String>,
    pub pricing_amount: Option<i64>,
    pub pricing_currency: Option<String>,
}

pub async fn update_product_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateProductBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let mut product = match state.storage.get_product(id).await {
        Ok(Some(p)) => p,
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

    if let Some(v) = body.name {
        product.name = v;
    }
    if let Some(v) = body.description {
        product.description = v;
    }
    if let Some(v) = body.seat_count {
        product.seat_count = v;
    }
    if let Some(v) = body.expiry_policy {
        product.expiry_policy = v;
    }
    if let Some(v) = body.grace_period_days {
        product.grace_period_days = Some(v);
    }
    if let Some(v) = body.heartbeat_interval_secs {
        product.heartbeat_interval_secs = Some(v);
    }
    if let Some(v) = body.heartbeat_grace_secs {
        product.heartbeat_grace_secs = Some(v);
    }
    if let Some(v) = body.shutdown_countdown_secs {
        product.shutdown_countdown_secs = Some(v);
    }
    if let Some(v) = body.auto_quarantine_on_critical {
        product.auto_quarantine_on_critical = v;
    }
    if let Some(v) = body.bundle_version {
        product.bundle_version = v;
    }
    if let Some(v) = body.min_client_version_warning {
        product.min_client_version_warning = Some(v);
    }
    if let Some(v) = body.min_client_version_required {
        product.min_client_version_required = Some(v);
    }
    if let Some(v) = body.pricing_amount {
        product.pricing_amount = v;
    }
    if let Some(v) = body.pricing_currency {
        product.pricing_currency = v;
    }
    product.updated_at = now_ns();

    if let Err(e) = state.storage.update_product(&product).await {
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
            AuditAction::ProductUpdate,
            AuditTargetType::Product,
            Some(id),
            None,
        ),
    )
    .await;

    Json(product_to_json(&product, state.payment_sandbox)).into_response()
}

pub async fn delete_product_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    if state.storage.get_product(id).await.ok().flatten().is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    match state.storage.count_licenses_for_product(id).await {
        Ok(count) if count > 0 => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error":"license_has_been_issued","message":"cannot delete product: a license has already been issued","payment_sandbox":state.payment_sandbox})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error","message":e.to_string()})),
            )
                .into_response()
        }
        _ => {}
    }

    if let Err(e) = state.storage.delete_product(id).await {
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
            AuditAction::ProductDelete,
            AuditTargetType::Product,
            Some(id),
            None,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

pub async fn activate_product_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let product = match state.storage.get_product(id).await {
        Ok(Some(p)) => p,
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

    let mut conditions: Vec<&str> = Vec::new();

    if state
        .storage
        .get_term_declaration(id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        conditions.push("term_declarations_missing");
    }

    if state
        .storage
        .get_active_terms_document(id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        conditions.push("active_terms_document_missing");
    }

    if state
        .storage
        .get_customer_fields(id)
        .await
        .map_or(true, |f| f.is_empty())
    {
        conditions.push("customer_fields_missing");
    }

    if product.pricing_amount == 0 && product.connectivity_mode != ConnectivityMode::AirGapped {
        conditions.push("pricing_not_configured");
    }

    if !conditions.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "activation_conditions_not_met",
                "conditions": conditions,
                "payment_sandbox": state.payment_sandbox
            })),
        )
            .into_response();
    }

    let mut updated = product;
    updated.active = true;
    updated.updated_at = now_ns();

    if let Err(e) = state.storage.update_product(&updated).await {
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
            AuditAction::ProductActivate,
            AuditTargetType::Product,
            Some(id),
            None,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}
