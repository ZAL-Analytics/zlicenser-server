pub mod audit;
pub mod auth;
pub mod customers;
pub mod licenses;
pub mod products;
pub mod security;
pub mod state;
pub mod terms;
pub mod transfers;
pub mod util;
pub mod vendor;

use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::storage::Storage;
use state::DashboardState;

pub fn build_dashboard_challenge_router<S: Storage + Clone + Send + Sync + 'static>(
    state: Arc<DashboardState<S>>,
) -> Router {
    Router::new()
        .route("/api/auth/challenge", post(auth::challenge_handler::<S>))
        .with_state(state)
}

pub fn build_dashboard_login_verify_router<S: Storage + Clone + Send + Sync + 'static>(
    state: Arc<DashboardState<S>>,
) -> Router {
    Router::new()
        .route("/api/auth/verify", post(auth::verify_handler::<S>))
        .route("/api/auth/login", post(auth::login_handler::<S>))
        .with_state(state)
}

#[allow(clippy::too_many_lines)]
pub fn build_dashboard_router<S: Storage + Clone + Send + Sync + 'static>(
    state: Arc<DashboardState<S>>,
) -> Router {
    Router::new()
        // auth (no rate limit)
        .route("/api/auth/logout", post(auth::logout_handler::<S>))
        .route("/api/auth/session", get(auth::session_info_handler::<S>))
        .route("/api/auth/password", post(auth::password_stub_handler::<S>))
        // products
        .route(
            "/api/products",
            get(products::list_products_handler::<S>).post(products::create_product_handler::<S>),
        )
        .route(
            "/api/products/{id}",
            get(products::get_product_handler::<S>)
                .patch(products::update_product_handler::<S>)
                .delete(products::delete_product_handler::<S>),
        )
        .route(
            "/api/products/{id}/activate",
            post(products::activate_product_handler::<S>),
        )
        // terms & declarations
        .route(
            "/api/products/{id}/declarations",
            get(terms::get_declarations_handler::<S>).put(terms::put_declarations_handler::<S>),
        )
        .route(
            "/api/products/{id}/terms/template",
            get(terms::get_terms_template_handler::<S>),
        )
        .route(
            "/api/products/{id}/terms",
            get(terms::list_terms_handler::<S>).post(terms::upload_terms_handler::<S>),
        )
        .route(
            "/api/products/{id}/terms/{doc_id}",
            get(terms::get_terms_document_handler::<S>),
        )
        .route(
            "/api/products/{id}/terms/{doc_id}/acknowledge",
            post(terms::acknowledge_terms_handler::<S>),
        )
        // customer fields
        .route(
            "/api/products/{id}/fields",
            get(terms::get_fields_handler::<S>).put(terms::put_fields_handler::<S>),
        )
        // bundle versions
        .route(
            "/api/products/{id}/versions",
            get(terms::get_versions_handler::<S>).patch(terms::patch_versions_handler::<S>),
        )
        .route(
            "/api/products/{id}/versions/policies",
            post(terms::create_policy_handler::<S>),
        )
        .route(
            "/api/products/{id}/versions/policies/{policy_id}",
            delete(terms::delete_policy_handler::<S>),
        )
        // client versions
        .route(
            "/api/products/{id}/client-versions",
            get(licenses::client_versions_handler::<S>),
        )
        // licenses
        .route("/api/licenses", get(licenses::list_licenses_handler::<S>))
        .route(
            "/api/licenses/{id}",
            get(licenses::get_license_handler::<S>),
        )
        .route(
            "/api/licenses/{id}/revoke",
            post(licenses::revoke_license_handler::<S>),
        )
        .route(
            "/api/licenses/{id}/evidence-bundle",
            get(licenses::evidence_bundle_stub_handler::<S>),
        )
        // customers
        .route(
            "/api/customers",
            get(customers::list_customers_handler::<S>),
        )
        .route(
            "/api/customers/{id}",
            get(customers::get_customer_handler::<S>),
        )
        .route(
            "/api/customers/{customer_id}/revoke-all",
            post(licenses::revoke_all_customer_licenses_handler::<S>),
        )
        // transfers
        .route(
            "/api/transfers",
            get(transfers::list_transfers_handler::<S>),
        )
        .route(
            "/api/transfers/{id}/approve",
            post(transfers::approve_transfer_handler::<S>),
        )
        .route(
            "/api/transfers/{id}/reject",
            post(transfers::reject_transfer_handler::<S>),
        )
        // security events & bindings
        .route(
            "/api/security-events",
            get(security::list_security_events_handler::<S>),
        )
        .route(
            "/api/security-events/{id}/review",
            post(security::review_security_event_handler::<S>),
        )
        .route(
            "/api/security-events/{id}/false-positive",
            post(security::false_positive_handler::<S>),
        )
        .route(
            "/api/bindings/{id}/quarantine",
            post(security::quarantine_binding_handler::<S>),
        )
        .route(
            "/api/bindings/{id}/terminate",
            post(security::terminate_binding_handler::<S>),
        )
        .route(
            "/api/bindings/{id}/resume",
            post(security::resume_binding_handler::<S>),
        )
        // vendor
        .route("/api/vendor", get(vendor::get_vendor_handler::<S>))
        // audit log
        .route("/api/audit-log", get(audit::list_audit_log_handler::<S>))
        .with_state(state)
}
