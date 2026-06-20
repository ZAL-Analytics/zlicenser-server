use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::auth::extract_session;
use super::state::DashboardState;
use super::util::format_ns_as_rfc3339;
use crate::storage::{Customer, Storage};

fn customer_to_json(c: &Customer, test_mode: bool) -> Value {
    json!({
        "id": c.id,
        "product_id": c.product_id,
        "full_name": c.full_name,
        "email": c.email,
        "field_values": c.field_values,
        "created_at": format_ns_as_rfc3339(c.created_at),
        "updated_at": format_ns_as_rfc3339(c.updated_at),
        "test_mode": test_mode,
    })
}

#[allow(clippy::implicit_hasher)]
pub async fn list_customers_handler<S: Storage + Clone + Send + Sync + 'static>(
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

    match state.storage.list_customers(product_id).await {
        Ok(customers) => {
            let items: Vec<Value> = customers
                .iter()
                .map(|c| customer_to_json(c, state.test_mode))
                .collect();
            Json(json!({"items": items, "test_mode": state.test_mode})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn get_customer_handler<S: Storage + Clone + Send + Sync + 'static>(
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
    match state.storage.get_customer(id).await {
        Ok(Some(c)) => Json(customer_to_json(&c, state.test_mode)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","test_mode":state.test_mode})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}
