use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Verifier};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::auth::extract_session;
use super::rbac::Permission;
use super::state::DashboardState;
use super::util::{append_audit, format_ns_as_rfc3339, new_audit_entry, now_ns};
use crate::http::extract::{JsonBody, PathParam};
use crate::storage::{
    AuditAction, AuditTargetType, NewStaffUser, Role, StaffUser, StaffUserUpdate, Storage,
};

fn staff_user_json(u: &StaffUser) -> serde_json::Value {
    json!({
        "id": u.id,
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role.to_string(),
        "active": u.active,
        "created_at": format_ns_as_rfc3339(u.created_at),
        "last_login_at": u.last_login_at.map(format_ns_as_rfc3339),
    })
}

async fn verify_key_sig<S: Storage + Clone + Send + Sync + 'static>(
    state: &DashboardState<S>,
    nonce: &str,
    signature: &str,
) -> Result<(), Response> {
    if !state.auth.consume_challenge(nonce).await {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_or_expired_nonce"})),
        )
            .into_response());
    }
    let sig_bytes = B64.decode(signature).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_signature_encoding"})),
        )
            .into_response()
    })?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_signature_length"})),
        )
            .into_response()
    })?;
    let ed_sig = Signature::from_bytes(&sig_arr);
    state
        .verifying_key
        .verify(nonce.as_bytes(), &ed_sig)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"signature_verification_failed"})),
            )
                .into_response()
        })
}

pub async fn list_users_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::UsersManage) {
        return r;
    }
    match state.storage.list_staff_users().await {
        Ok(users) => {
            let items: Vec<_> = users.iter().map(staff_user_json).collect();
            Json(json!({"users": items})).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateUserBody {
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub password: String,
    pub nonce: String,
    pub signature: String,
}

pub async fn create_user_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<CreateUserBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::UsersManage) {
        return r;
    }
    if let Err(r) = verify_key_sig(&state, &body.nonce, &body.signature).await {
        return r;
    }

    let role: Role = match body.role.parse() {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_role"})),
            )
                .into_response();
        }
    };

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match Argon2::default().hash_password(body.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error"})),
            )
                .into_response();
        }
    };

    let now = now_ns();
    let new_user = NewStaffUser {
        id: Uuid::new_v4(),
        email: body.email,
        password_hash,
        display_name: body.display_name,
        role,
        created_by: session.user_id,
        created_at: now,
        updated_at: now,
    };

    match state.storage.create_staff_user(&new_user).await {
        Ok(user) => {
            append_audit(
                &*state.storage,
                new_audit_entry(
                    session.auth_method,
                    AuditAction::UserCreate,
                    AuditTargetType::User,
                    Some(user.id),
                    None,
                    session.user_id,
                ),
            )
            .await;
            (StatusCode::CREATED, Json(staff_user_json(&user))).into_response()
        }
        Err(e) if e.to_string().contains("UNIQUE") || e.to_string().contains("unique") => (
            StatusCode::CONFLICT,
            Json(json!({"error":"email_already_exists"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response(),
    }
}

pub async fn get_user_handler<S: Storage + Clone + Send + Sync + 'static>(
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
    if let Err(r) = session.require(Permission::UsersManage) {
        return r;
    }
    match state.storage.get_staff_user_by_id(id).await {
        Ok(Some(user)) => Json(staff_user_json(&user)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateUserBody {
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub nonce: String,
    pub signature: String,
}

pub async fn update_user_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<UpdateUserBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::UsersManage) {
        return r;
    }
    if let Err(r) = verify_key_sig(&state, &body.nonce, &body.signature).await {
        return r;
    }

    let new_role: Option<Role> = match body.role.as_deref() {
        Some(s) => match s.parse() {
            Ok(r) => Some(r),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"invalid_role"})),
                )
                    .into_response();
            }
        },
        None => None,
    };

    if let Some(nr) = new_role
        && nr != Role::Owner
    {
        match state.storage.get_staff_user_by_id(id).await {
            Ok(Some(target)) if target.role == Role::Owner => {
                let Ok(count) = state.storage.count_active_owners().await else {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":"internal_error"})),
                    )
                        .into_response();
                };
                if count <= 1 {
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({"error":"cannot_downgrade_last_owner"})),
                    )
                        .into_response();
                }
            }
            Ok(_) => {}
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"internal_error"})),
                )
                    .into_response();
            }
        }
    }

    let update = StaffUserUpdate {
        display_name: body.display_name,
        role: new_role,
        active: None,
        password_hash: None,
        updated_at: now_ns(),
    };

    match state.storage.update_staff_user(id, &update).await {
        Ok(Some(user)) => {
            append_audit(
                &*state.storage,
                new_audit_entry(
                    session.auth_method,
                    AuditAction::UserRoleChange,
                    AuditTargetType::User,
                    Some(id),
                    None,
                    session.user_id,
                ),
            )
            .await;
            Json(staff_user_json(&user)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct KeySigBody {
    pub nonce: String,
    pub signature: String,
}

pub async fn deactivate_user_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<KeySigBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::UsersManage) {
        return r;
    }
    if let Err(r) = verify_key_sig(&state, &body.nonce, &body.signature).await {
        return r;
    }

    if session.user_id == Some(id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"cannot_deactivate_self"})),
        )
            .into_response();
    }

    match state.storage.get_staff_user_by_id(id).await {
        Ok(Some(target)) if target.role == Role::Owner => {
            let Ok(count) = state.storage.count_active_owners().await else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"internal_error"})),
                )
                    .into_response();
            };
            if count <= 1 {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error":"cannot_deactivate_last_owner"})),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response();
        }
        Ok(_) => {}
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error"})),
            )
                .into_response();
        }
    }

    let update = StaffUserUpdate {
        display_name: None,
        role: None,
        active: Some(false),
        password_hash: None,
        updated_at: now_ns(),
    };

    match state.storage.update_staff_user(id, &update).await {
        Ok(Some(user)) => {
            append_audit(
                &*state.storage,
                new_audit_entry(
                    session.auth_method,
                    AuditAction::UserDeactivate,
                    AuditTargetType::User,
                    Some(id),
                    None,
                    session.user_id,
                ),
            )
            .await;
            Json(staff_user_json(&user)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response(),
    }
}

pub async fn reactivate_user_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    PathParam(id): PathParam<Uuid>,
    JsonBody(body): JsonBody<KeySigBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };
    if let Err(r) = session.require(Permission::UsersManage) {
        return r;
    }
    if let Err(r) = verify_key_sig(&state, &body.nonce, &body.signature).await {
        return r;
    }

    let update = StaffUserUpdate {
        display_name: None,
        role: None,
        active: Some(true),
        password_hash: None,
        updated_at: now_ns(),
    };

    match state.storage.update_staff_user(id, &update).await {
        Ok(Some(user)) => {
            append_audit(
                &*state.storage,
                new_audit_entry(
                    session.auth_method,
                    AuditAction::UserReactivate,
                    AuditTargetType::User,
                    Some(id),
                    None,
                    session.user_id,
                ),
            )
            .await;
            Json(staff_user_json(&user)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordBody {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_own_password_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
    JsonBody(body): JsonBody<ChangePasswordBody>,
) -> Response {
    let Ok(session) = extract_session(&headers, &state).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    };

    let Some(user_id) = session.user_id else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"key_sessions_cannot_change_password"})),
        )
            .into_response();
    };

    let user = match state.storage.get_staff_user_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error"})),
            )
                .into_response();
        }
    };

    let Ok(parsed) = PasswordHash::new(&user.password_hash) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"internal_error"})),
        )
            .into_response();
    };

    if Argon2::default()
        .verify_password(body.current_password.as_bytes(), &parsed)
        .is_err()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response();
    }

    let salt = SaltString::generate(&mut OsRng);
    let new_hash = match Argon2::default().hash_password(body.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error"})),
            )
                .into_response();
        }
    };

    let update = StaffUserUpdate {
        display_name: None,
        role: None,
        active: None,
        password_hash: Some(new_hash),
        updated_at: now_ns(),
    };

    match state.storage.update_staff_user(user_id, &update).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error":"not_found"}))).into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error":"internal_error"})),
            )
                .into_response();
        }
    }

    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::OwnPasswordChange,
            AuditTargetType::User,
            Some(user_id),
            None,
            session.user_id,
        ),
    )
    .await;

    Json(json!({"ok": true})).into_response()
}
