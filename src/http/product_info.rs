use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use uuid::Uuid;

use crate::storage::Storage;

#[derive(Clone)]
pub struct ProductInfoState<S: Storage + Clone> {
    pub storage: Arc<S>,
}

pub async fn product_info_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<ProductInfoState<S>>,
    Path(product_id): Path<Uuid>,
) -> impl IntoResponse {
    let product = match state.storage.get_product(product_id).await {
        Ok(Some(p)) if p.active => p,
        Ok(_) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal_error"})),
            )
                .into_response();
        }
    };

    let terms = state
        .storage
        .get_term_declaration(product_id)
        .await
        .unwrap_or(None);

    let connectivity_description = match product.connectivity_mode {
        crate::storage::types::ConnectivityMode::AirGapped => {
            "Works fully offline; no internet connectivity required"
        }
        crate::storage::types::ConnectivityMode::Online => {
            "Requires periodic internet connectivity for heartbeats"
        }
        crate::storage::types::ConnectivityMode::AlwaysOnline => {
            "Requires continuous internet connectivity"
        }
    };

    let terms_summary = terms.as_ref().map(|t| {
        json!({
            "warranty": t.warranty,
            "refund": t.refund,
            "revocation": t.revocation,
            "expiry": t.expiry,
            "support_available": t.support_available,
            "support_channels": t.support_channels,
            "updates_policy": t.updates_policy,
        })
    });

    let body = json!({
        "id": product.id,
        "name": product.name,
        "connectivity_mode": product.connectivity_mode.to_string(),
        "connectivity_description": connectivity_description,
        "tsa_tier": product.tsa_tier.to_string(),
        "pricing": {
            "amount": product.pricing_amount,
            "currency": product.pricing_currency,
        },
        "min_client_version_warning": product.min_client_version_warning,
        "min_client_version_required": product.min_client_version_required,
        "terms_summary": terms_summary,
    });

    (StatusCode::OK, Json(body)).into_response()
}
