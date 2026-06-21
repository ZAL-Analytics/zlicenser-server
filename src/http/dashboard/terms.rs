use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::http::extract::{JsonBody, PathParam};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::auth::extract_session;
use super::rbac::Permission;
use super::state::DashboardState;
use super::util::{append_audit, format_ns_as_rfc3339, new_audit_entry, now_ns};
use crate::storage::{
    AuditAction, AuditTargetType, GdprBasis, ProductCustomerField, ProductTermDeclaration,
    ProductTermsDocument, Storage, TermsValidationStatus, UpgradePolicy, UpgradePolicyRow,
};

fn declaration_to_json(d: &ProductTermDeclaration, payment_sandbox: bool) -> Value {
    json!({
        "product_id": d.product_id,
        "warranty": d.warranty,
        "refund": d.refund,
        "revocation": d.revocation,
        "expiry": d.expiry,
        "support_available": d.support_available,
        "support_channels": d.support_channels,
        "response_sla_hours": d.response_sla_hours,
        "support_scope": d.support_scope,
        "support_coverage": d.support_coverage,
        "updates_policy": d.updates_policy,
        "payment_sandbox": payment_sandbox,
    })
}

fn terms_doc_to_json(d: &ProductTermsDocument, payment_sandbox: bool) -> Value {
    json!({
        "id": d.id,
        "product_id": d.product_id,
        "rendered_hash": d.rendered_hash,
        "validation_status": d.validation_status.to_string(),
        "validation_findings": d.validation_findings,
        "vendor_acknowledged_at": d.vendor_acknowledged_at.map(format_ns_as_rfc3339),
        "activated_at": d.activated_at.map(format_ns_as_rfc3339),
        "created_at": format_ns_as_rfc3339(d.created_at),
        "payment_sandbox": payment_sandbox,
    })
}

fn field_to_json(f: &ProductCustomerField, payment_sandbox: bool) -> Value {
    json!({
        "id": f.id,
        "product_id": f.product_id,
        "field_key": f.field_key,
        "required": f.required,
        "gdpr_basis": f.gdpr_basis.to_string(),
        "purpose_description": f.purpose_description,
        "payment_sandbox": payment_sandbox,
    })
}

fn policy_to_json(p: &UpgradePolicyRow, payment_sandbox: bool) -> Value {
    json!({
        "id": p.id,
        "product_id": p.product_id,
        "from_version": p.from_version,
        "to_version": p.to_version,
        "policy": p.policy.to_string(),
        "created_at": format_ns_as_rfc3339(p.created_at),
        "payment_sandbox": payment_sandbox,
    })
}

pub async fn get_declarations_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsRead) {
        return r;
    }
    match state.storage.get_term_declaration(id).await {
        Ok(Some(d)) => Json(declaration_to_json(&d, state.payment_sandbox)).into_response(),
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
pub struct PutDeclarationsBody {
    pub warranty: String,
    pub refund: String,
    pub revocation: String,
    pub expiry: String,
    pub support_available: bool,
    pub support_channels: String,
    pub response_sla_hours: Option<i64>,
    pub support_scope: Option<String>,
    pub support_coverage: Option<String>,
    pub updates_policy: String,
}

pub async fn put_declarations_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<PutDeclarationsBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

    if state.storage.get_product(id).await.ok().flatten().is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let decl = ProductTermDeclaration {
        product_id: id,
        warranty: body.warranty,
        refund: body.refund,
        revocation: body.revocation,
        expiry: body.expiry,
        support_available: body.support_available,
        support_channels: body.support_channels,
        response_sla_hours: body.response_sla_hours,
        support_scope: body.support_scope,
        support_coverage: body.support_coverage,
        updates_policy: body.updates_policy,
    };

    if let Err(e) = state.storage.upsert_term_declaration(&decl).await {
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
            AuditAction::DeclarationsUpdate,
            AuditTargetType::Product,
            Some(id),
            None,
            session.user_id,
        ),
    )
    .await;

    Json(declaration_to_json(&decl, state.payment_sandbox)).into_response()
}

pub async fn get_terms_template_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsRead) {
        return r;
    }

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

    let decl = state.storage.get_term_declaration(id).await.ok().flatten();

    let warranty = decl.as_ref().map_or("", |d| d.warranty.as_str());
    let refund = decl.as_ref().map_or("", |d| d.refund.as_str());
    let revocation = decl.as_ref().map_or("", |d| d.revocation.as_str());
    let expiry = decl.as_ref().map_or("", |d| d.expiry.as_str());
    let updates = decl.as_ref().map_or("", |d| d.updates_policy.as_str());

    let typst_source = format!(
        r#"#import "@preview/basic-document:0.1.0": *

= License Terms for {name}

== 1. Warranty

{warranty}

== 2. Refund Policy

{refund}

== 3. Revocation Policy

{revocation}

== 4. License Expiry

{expiry}

== 5. Updates Policy

{updates}

// -- Add your additional legal text below ---
"#,
        name = product.name,
        warranty = warranty,
        refund = refund,
        revocation = revocation,
        expiry = expiry,
        updates = updates,
    );

    let product_name_safe: String = product.name.replace(' ', "-").to_ascii_lowercase();
    let now = now_ns();
    let secs = u64::try_from(now / 1_000_000_000).unwrap_or_default();
    let filename = format!("{product_name_safe}-terms-{secs}.typ");

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{filename}\""),
            ),
        ],
        typst_source,
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UploadTermsBody {
    pub typst_source: String,
}

fn validate_terms(source: &str) -> (TermsValidationStatus, Vec<Value>) {
    let mut findings: Vec<Value> = Vec::new();
    let lower = source.to_ascii_lowercase();

    for section in ["warranty", "refund", "revocation", "expiry"] {
        if !lower.contains(section) {
            findings.push(json!({
                "level": "Error",
                "message": format!("Required section '{}' not found in document", section)
            }));
        }
    }

    if source.len() < 200 {
        findings.push(json!({
            "level": "Warning",
            "message": "Document appears very short; ensure all required clauses are present"
        }));
    }

    let status = if findings.iter().any(|f| f["level"] == "Error") {
        TermsValidationStatus::Conflicts
    } else if findings.is_empty() {
        TermsValidationStatus::Valid
    } else {
        TermsValidationStatus::Warnings
    };

    (status, findings)
}

pub async fn upload_terms_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<UploadTermsBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

    if state.storage.get_product(id).await.ok().flatten().is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let (validation_status, findings) = validate_terms(&body.typst_source);
    let findings_json = serde_json::to_string(&findings).unwrap_or_else(|_| "[]".to_owned());

    let mut hasher = DefaultHasher::new();
    body.typst_source.hash(&mut hasher);
    let rendered_hash = format!("{:016x}", hasher.finish());

    let now = now_ns();
    let doc = ProductTermsDocument {
        id: Uuid::new_v4(),
        product_id: id,
        typst_source: body.typst_source,
        rendered_hash,
        validation_status,
        validation_findings: findings_json.clone(),
        vendor_acknowledged_at: None,
        vendor_acknowledged_findings: None,
        activated_at: None,
        created_at: now,
    };

    if let Err(e) = state.storage.create_terms_document(&doc).await {
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
            AuditAction::TermsDocumentUpload,
            AuditTargetType::TermsDocument,
            Some(doc.id),
            None,
            session.user_id,
        ),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": doc.id,
            "product_id": doc.product_id,
            "validation_status": doc.validation_status.to_string(),
            "validation_findings": findings,
            "rendered_hash": doc.rendered_hash,
            "created_at": format_ns_as_rfc3339(doc.created_at),
            "payment_sandbox": state.payment_sandbox,
        })),
    )
        .into_response()
}

pub async fn list_terms_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsRead) {
        return r;
    }
    match state.storage.list_terms_documents(id).await {
        Ok(docs) => {
            let items: Vec<Value> = docs
                .iter()
                .map(|d| terms_doc_to_json(d, state.payment_sandbox))
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

pub async fn get_terms_document_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam((_product_id, doc_id)): PathParam<(Uuid, Uuid)>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsRead) {
        return r;
    }
    match state.storage.get_terms_document(doc_id).await {
        Ok(Some(d)) => Json(terms_doc_to_json(&d, state.payment_sandbox)).into_response(),
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

pub async fn acknowledge_terms_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam((_product_id, doc_id)): PathParam<(Uuid, Uuid)>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

    let doc = match state.storage.get_terms_document(doc_id).await {
        Ok(Some(d)) => d,
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

    match doc.validation_status {
        TermsValidationStatus::Conflicts | TermsValidationStatus::PendingReview => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "document_not_ready",
                    "status": doc.validation_status.to_string(),
                    "payment_sandbox": state.payment_sandbox,
                })),
            )
                .into_response();
        }
        TermsValidationStatus::Valid | TermsValidationStatus::Warnings => {}
    }

    if doc.activated_at.is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"already_activated","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let now = now_ns();
    if doc.validation_status == TermsValidationStatus::Warnings
        && let Err(e) = state
            .storage
            .acknowledge_terms_findings(doc_id, now, &doc.validation_findings)
            .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response();
    }

    if let Err(e) = state.storage.activate_terms_document(doc_id, now).await {
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
            AuditAction::TermsDocumentAcknowledge,
            AuditTargetType::TermsDocument,
            Some(doc_id),
            None,
            session.user_id,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

pub async fn get_fields_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsRead) {
        return r;
    }
    match state.storage.get_customer_fields(id).await {
        Ok(fields) => {
            let items: Vec<Value> = fields
                .iter()
                .map(|f| field_to_json(f, state.payment_sandbox))
                .collect();
            Json(json!({"fields": items, "payment_sandbox": state.payment_sandbox})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error","message":e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct FieldBody {
    pub field_key: String,
    pub required: bool,
    pub gdpr_basis: String,
    pub purpose_description: Option<String>,
}

#[derive(Deserialize)]
pub struct PutFieldsBody {
    pub fields: Vec<FieldBody>,
}

pub async fn put_fields_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<PutFieldsBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

    if state.storage.get_product(id).await.ok().flatten().is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let fields: Vec<ProductCustomerField> = body
        .fields
        .into_iter()
        .map(|f| {
            let gdpr_basis = f
                .gdpr_basis
                .parse::<GdprBasis>()
                .unwrap_or(GdprBasis::Contract);
            ProductCustomerField {
                id: Uuid::new_v4(),
                product_id: id,
                field_key: f.field_key,
                required: f.required,
                gdpr_basis,
                purpose_description: f.purpose_description,
            }
        })
        .collect();

    if let Err(e) = state.storage.replace_customer_fields(id, &fields).await {
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
            AuditAction::CustomerFieldsUpdate,
            AuditTargetType::Product,
            Some(id),
            None,
            session.user_id,
        ),
    )
    .await;

    let items: Vec<Value> = fields
        .iter()
        .map(|f| field_to_json(f, state.payment_sandbox))
        .collect();
    Json(json!({"fields": items, "payment_sandbox": state.payment_sandbox})).into_response()
}

pub async fn get_versions_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsRead) {
        return r;
    }

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

    let policies = match state.storage.list_upgrade_policies(id).await {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error","message":e.to_string()})),
            )
                .into_response();
        }
    };

    let policy_items: Vec<Value> = policies
        .iter()
        .map(|p| policy_to_json(p, state.payment_sandbox))
        .collect();

    Json(json!({
        "bundle_version": product.bundle_version,
        "min_client_version_warning": product.min_client_version_warning,
        "min_client_version_required": product.min_client_version_required,
        "upgrade_policies": policy_items,
        "payment_sandbox": state.payment_sandbox,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct PatchVersionsBody {
    pub bundle_version: Option<String>,
    pub min_client_version_warning: Option<String>,
    pub min_client_version_required: Option<String>,
}

pub async fn patch_versions_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<PatchVersionsBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

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

    if let Some(v) = body.bundle_version {
        product.bundle_version = v;
    }
    if let Some(v) = body.min_client_version_warning {
        product.min_client_version_warning = Some(v);
    }
    if let Some(v) = body.min_client_version_required {
        product.min_client_version_required = Some(v);
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
            AuditAction::BundleVersionUpdate,
            AuditTargetType::Product,
            Some(id),
            None,
            session.user_id,
        ),
    )
    .await;

    Json(json!({
        "bundle_version": product.bundle_version,
        "min_client_version_warning": product.min_client_version_warning,
        "min_client_version_required": product.min_client_version_required,
        "payment_sandbox": state.payment_sandbox,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CreatePolicyBody {
    pub from_version: String,
    pub to_version: String,
    pub policy: String,
}

pub async fn create_policy_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<CreatePolicyBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

    if state.storage.get_product(id).await.ok().flatten().is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let Ok(policy) = body.policy.parse::<UpgradePolicy>() else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":"bad_request","message":"invalid policy","payment_sandbox":state.payment_sandbox}))).into_response();
    };

    let row = UpgradePolicyRow {
        id: Uuid::new_v4(),
        product_id: id,
        from_version: body.from_version,
        to_version: body.to_version,
        policy,
        created_at: now_ns(),
    };

    if let Err(e) = state.storage.create_upgrade_policy(&row).await {
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
            AuditAction::UpgradePolicyCreate,
            AuditTargetType::Product,
            Some(id),
            None,
            session.user_id,
        ),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(policy_to_json(&row, state.payment_sandbox)),
    )
        .into_response()
}

pub async fn delete_policy_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam((_product_id, policy_id)): PathParam<(Uuid, Uuid)>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::TermsWrite) {
        return r;
    }

    if state
        .storage
        .get_upgrade_policy(policy_id)
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

    if let Err(e) = state.storage.delete_upgrade_policy(policy_id).await {
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
            AuditAction::UpgradePolicyDelete,
            AuditTargetType::Product,
            Some(policy_id),
            None,
            session.user_id,
        ),
    )
    .await;

    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}
