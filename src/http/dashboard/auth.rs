use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};

use super::rbac::Permission;
use super::state::DashboardState;
use super::util::{append_audit, format_rfc3339, new_audit_entry};
use crate::http::extract::JsonBody;
use crate::storage::{AuditAction, AuditAuthMethod, AuditTargetType, Role, Storage};

pub struct AuthenticatedSession {
    pub token: String,
    pub auth_method: AuditAuthMethod,
    pub user_id: Option<Uuid>,
    pub role: Role,
}

impl AuthenticatedSession {
    #[allow(clippy::result_large_err)]
    pub fn require(&self, perm: Permission) -> Result<(), Response> {
        if self.role.has(perm) {
            Ok(())
        } else {
            Err((StatusCode::FORBIDDEN, Json(json!({"error":"forbidden"}))).into_response())
        }
    }
}

pub async fn extract_session<S: Storage + Clone + Send + Sync + 'static>(
    headers: &HeaderMap,
    state: &DashboardState<S>,
) -> Result<AuthenticatedSession, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"unauthorized"})),
            )
                .into_response()
        })?;

    let auth_method = state.auth.session_auth_method(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response()
    })?;

    let user_id = state.auth.session_user_id(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response()
    })?;

    let role = state.auth.session_role(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        )
            .into_response()
    })?;

    Ok(AuthenticatedSession {
        token: token.to_owned(),
        auth_method,
        user_id,
        role,
    })
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub payment_sandbox: bool,
}

pub async fn challenge_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
) -> impl IntoResponse {
    let nonce = state.auth.new_challenge().await;
    Json(ChallengeResponse {
        nonce,
        payment_sandbox: state.payment_sandbox,
    })
}

#[derive(Deserialize)]
pub struct VerifyBody {
    pub nonce: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub payment_sandbox: bool,
}

pub async fn verify_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    JsonBody(body): JsonBody<VerifyBody>,
) -> Response {
    if !state.auth.consume_challenge(&body.nonce).await {
        append_audit(
            &*state.storage,
            new_audit_entry(
                AuditAuthMethod::KeyBased,
                AuditAction::LoginFailed,
                AuditTargetType::Auth,
                None,
                Some("invalid or expired nonce".to_owned()),
                None,
            ),
        )
        .await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let Ok(sig_bytes) = B64.decode(&body.signature) else {
        append_audit(
            &*state.storage,
            new_audit_entry(
                AuditAuthMethod::KeyBased,
                AuditAction::LoginFailed,
                AuditTargetType::Auth,
                None,
                Some("invalid signature encoding".to_owned()),
                None,
            ),
        )
        .await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    };

    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"unauthorized","payment_sandbox":state.payment_sandbox})),
            )
                .into_response();
        }
    };
    let signature = Signature::from_bytes(&sig_arr);
    let nonce_bytes = body.nonce.as_bytes();

    if state.verifying_key.verify(nonce_bytes, &signature).is_err() {
        append_audit(
            &*state.storage,
            new_audit_entry(
                AuditAuthMethod::KeyBased,
                AuditAction::LoginFailed,
                AuditTargetType::Auth,
                None,
                Some("signature verification failed".to_owned()),
                None,
            ),
        )
        .await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized","payment_sandbox":state.payment_sandbox})),
        )
            .into_response();
    }

    let token = state
        .auth
        .new_session(AuditAuthMethod::KeyBased, None, Role::Owner)
        .await;
    append_audit(
        &*state.storage,
        new_audit_entry(
            AuditAuthMethod::KeyBased,
            AuditAction::LoginSuccess,
            AuditTargetType::Auth,
            None,
            None,
            None,
        ),
    )
    .await;
    Json(TokenResponse {
        token,
        payment_sandbox: state.payment_sandbox,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
}

fn unauthorized_response(payment_sandbox: bool) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error":"unauthorized","payment_sandbox":payment_sandbox})),
    )
        .into_response()
}

pub async fn login_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    JsonBody(body): JsonBody<LoginBody>,
) -> Response {
    let user = match state.storage.get_staff_user_by_email(&body.email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            append_audit(
                &*state.storage,
                new_audit_entry(
                    AuditAuthMethod::Password,
                    AuditAction::LoginFailed,
                    AuditTargetType::Auth,
                    None,
                    None,
                    None,
                ),
            )
            .await;
            return unauthorized_response(state.payment_sandbox);
        }
        Err(_) => return unauthorized_response(state.payment_sandbox),
    };

    let Ok(parsed) = PasswordHash::new(&user.password_hash) else {
        return unauthorized_response(state.payment_sandbox);
    };

    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
        || !user.active
    {
        append_audit(
            &*state.storage,
            new_audit_entry(
                AuditAuthMethod::Password,
                AuditAction::LoginFailed,
                AuditTargetType::Auth,
                None,
                None,
                None,
            ),
        )
        .await;
        return unauthorized_response(state.payment_sandbox);
    }

    let _ = state
        .storage
        .update_staff_user_last_login(user.id, super::util::now_ns())
        .await;

    let token = state
        .auth
        .new_session(AuditAuthMethod::Password, Some(user.id), user.role)
        .await;
    append_audit(
        &*state.storage,
        new_audit_entry(
            AuditAuthMethod::Password,
            AuditAction::LoginSuccess,
            AuditTargetType::Auth,
            None,
            None,
            Some(user.id),
        ),
    )
    .await;
    Json(TokenResponse {
        token,
        payment_sandbox: state.payment_sandbox,
    })
    .into_response()
}

pub async fn logout_handler<S: Storage + Clone + Send + Sync + 'static>(
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
    state.auth.invalidate_session(&session.token).await;
    append_audit(
        &*state.storage,
        new_audit_entry(
            session.auth_method,
            AuditAction::Logout,
            AuditTargetType::Auth,
            None,
            None,
            session.user_id,
        ),
    )
    .await;
    Json(json!({"ok":true,"payment_sandbox":state.payment_sandbox})).into_response()
}

#[derive(Serialize)]
pub struct SessionInfoResponse {
    pub expires_at: String,
    pub role: String,
    pub user_id: Option<Uuid>,
    pub payment_sandbox: bool,
}

pub async fn session_info_handler<S: Storage + Clone + Send + Sync + 'static>(
    State(state): State<Arc<DashboardState<S>>>,
    headers: HeaderMap,
) -> Response {
    let token = match headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_owned(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"unauthorized"})),
            )
                .into_response();
        }
    };

    let (expires_at, role, user_id) = match state.auth.session_expires_at(&token).await {
        Some(instant) => {
            let now_instant = std::time::Instant::now();
            let now_sys = std::time::SystemTime::now();
            if instant <= now_instant {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error":"unauthorized"})),
                )
                    .into_response();
            }
            let offset = instant - now_instant;
            let sys_exp = now_sys + offset;
            let epoch_secs = sys_exp
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let exp_str = format_rfc3339(epoch_secs);
            let role = state
                .auth
                .session_role(&token)
                .await
                .unwrap_or(Role::Auditor);
            let user_id = state.auth.session_user_id(&token).await.flatten();
            (exp_str, role, user_id)
        }
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"unauthorized"})),
            )
                .into_response();
        }
    };

    Json(SessionInfoResponse {
        expires_at,
        role: role.to_string(),
        user_id,
        payment_sandbox: state.payment_sandbox,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::super::util::now_ns;
    use super::*;

    #[test]
    fn format_rfc3339_known_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(86400), "1970-01-02T00:00:00Z");
        assert_eq!(format_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
    }

    #[test]
    fn now_ns_is_positive() {
        assert!(now_ns() > 0);
    }
}
