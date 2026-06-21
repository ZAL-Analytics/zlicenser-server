#![allow(dead_code)]

#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
#[allow(unused_imports)]
pub use sqlite_fns::*;

#[cfg(feature = "http-server")]
pub mod with_storage {
    use std::sync::Arc;

    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString},
    };
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use zlicenser_server::{
        http::dashboard::{
            build_dashboard_challenge_router, build_dashboard_login_verify_router,
            build_dashboard_router, state::DashboardState,
        },
        storage::{NewStaffUser, Role, StaffUserUpdate, Storage, VendorConfig},
    };

    pub fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    pub fn make_state<S: Storage + Clone + Send + Sync + 'static>(
        storage: Arc<S>,
        signing_key: &SigningKey,
    ) -> Arc<DashboardState<S>> {
        DashboardState::new(storage, signing_key.verifying_key(), true)
    }

    pub fn build_router<S: Storage + Clone + Send + Sync + 'static>(
        state: Arc<DashboardState<S>>,
    ) -> Router {
        build_dashboard_challenge_router(Arc::clone(&state))
            .merge(build_dashboard_login_verify_router(Arc::clone(&state)))
            .merge(build_dashboard_router(state))
    }

    async fn call(router: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn json_post(
        router: Router,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        call(router, req).await
    }

    async fn authed_get(router: Router, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        call(router, req).await
    }

    async fn authed_post(
        router: Router,
        uri: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        call(router, req).await
    }

    async fn authed_patch(
        router: Router,
        uri: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("PATCH")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        call(router, req).await
    }

    async fn challenge_nonce<S: Storage + Clone + Send + Sync + 'static>(
        router: &Router,
        state: &Arc<DashboardState<S>>,
    ) -> String {
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/challenge")
            .body(Body::empty())
            .unwrap();
        let (_status, body) = call(router.clone(), req).await;
        let _ = state;
        body["nonce"].as_str().unwrap().to_owned()
    }

    async fn get_key_token<S: Storage + Clone + Send + Sync + 'static>(
        router: &Router,
        state: &Arc<DashboardState<S>>,
        signing_key: &SigningKey,
    ) -> String {
        let nonce = challenge_nonce(router, state).await;
        let sig = signing_key.sign(nonce.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        let (status, body) = json_post(
            router.clone(),
            "/api/auth/verify",
            serde_json::json!({"nonce": nonce, "signature": sig_b64}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "verify failed: {body}");
        body["token"].as_str().unwrap().to_owned()
    }

    async fn get_password_token<S: Storage + Clone + Send + Sync + 'static>(
        router: &Router,
        _state: &Arc<DashboardState<S>>,
        email: &str,
        password: &str,
    ) -> String {
        let (status, body) = json_post(
            router.clone(),
            "/api/auth/login",
            serde_json::json!({"email": email, "password": password}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "login failed: {body}");
        body["token"].as_str().unwrap().to_owned()
    }

    async fn get_nonce_and_sig<S: Storage + Clone + Send + Sync + 'static>(
        router: &Router,
        state: &Arc<DashboardState<S>>,
        signing_key: &SigningKey,
    ) -> (String, String) {
        let nonce = challenge_nonce(router, state).await;
        let sig = signing_key.sign(nonce.as_bytes());
        (nonce, B64.encode(sig.to_bytes()))
    }

    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("argon2 hash failed in test")
            .to_string()
    }

    fn now_ns() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64
    }

    pub async fn create_owner_user<S: Storage + Clone + Send + Sync + 'static>(
        storage: &Arc<S>,
        email: &str,
        password: &str,
    ) -> Uuid {
        let now = now_ns();
        let new_user = NewStaffUser {
            id: Uuid::new_v4(),
            email: email.to_owned(),
            password_hash: hash_password(password),
            display_name: "Test Owner".to_owned(),
            role: Role::Owner,
            created_by: None,
            created_at: now,
            updated_at: now,
        };
        storage
            .create_staff_user(&new_user)
            .await
            .expect("create_owner_user failed")
            .id
    }

    pub async fn create_user_with_role<S: Storage + Clone + Send + Sync + 'static>(
        storage: &Arc<S>,
        role: Role,
        email: &str,
        password: &str,
    ) -> Uuid {
        let now = now_ns();
        let new_user = NewStaffUser {
            id: Uuid::new_v4(),
            email: email.to_owned(),
            password_hash: hash_password(password),
            display_name: format!("Test {role}"),
            role,
            created_by: None,
            created_at: now,
            updated_at: now,
        };
        storage
            .create_staff_user(&new_user)
            .await
            .expect("create_user_with_role failed")
            .id
    }

    pub async fn test_challenge_returns_nonce_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/challenge")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(router, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body["nonce"].as_str().unwrap_or("").is_empty());
        assert_eq!(body["payment_sandbox"], true);
    }

    pub async fn test_challenge_nonces_are_unique_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let n1 = challenge_nonce(&router, &state).await;
        let n2 = challenge_nonce(&router, &state).await;
        assert_ne!(n1, n2);
    }

    pub async fn test_verify_with_valid_key_returns_token_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        assert!(!token.is_empty());
    }

    pub async fn test_verify_with_invalid_sig_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let nonce = challenge_nonce(&router, &state).await;
        let bad_sig = B64.encode([0u8; 64]);
        let (status, _) = json_post(
            router,
            "/api/auth/verify",
            serde_json::json!({"nonce": nonce, "signature": bad_sig}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_verify_with_wrong_key_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let wrong_key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let nonce = challenge_nonce(&router, &state).await;
        let sig = wrong_key.sign(nonce.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        let (status, _) = json_post(
            router,
            "/api/auth/verify",
            serde_json::json!({"nonce": nonce, "signature": sig_b64}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_login_unknown_user_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let (status, _) = json_post(
            router,
            "/api/auth/login",
            serde_json::json!({"email": "nobody@example.com", "password": "anything"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_login_correct_password_returns_token_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_owner_user(&s, "owner@example.com", "testpass").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "owner@example.com", "testpass").await;
        assert!(!token.is_empty());
    }

    pub async fn test_login_wrong_password_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_owner_user(&s, "owner@example.com", "testpass").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let (status, _) = json_post(
            router,
            "/api/auth/login",
            serde_json::json!({"email": "owner@example.com", "password": "wrongpass"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_login_deactivated_user_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let user_id = create_owner_user(&s, "owner@example.com", "testpass").await;
        s.update_staff_user(
            user_id,
            &StaffUserUpdate {
                active: Some(false),
                updated_at: now_ns(),
                ..Default::default()
            },
        )
        .await
        .expect("deactivate in test failed");
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let (status, _) = json_post(
            router,
            "/api/auth/login",
            serde_json::json!({"email": "owner@example.com", "password": "testpass"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_key_session_has_owner_role_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/auth/session", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["role"], "Owner");
        assert!(body["user_id"].is_null());
    }

    pub async fn test_password_session_has_correct_role_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_user_with_role(&s, Role::Auditor, "auditor@example.com", "pass123").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "auditor@example.com", "pass123").await;
        let (status, body) = authed_get(router, "/api/auth/session", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["role"], "Auditor");
        assert!(body["user_id"].is_string());
    }

    pub async fn test_session_info_includes_role_and_user_id_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let user_id = create_owner_user(&s, "owner@example.com", "testpass").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "owner@example.com", "testpass").await;
        let (status, body) = authed_get(router, "/api/auth/session", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["role"], "Owner");
        assert_eq!(
            body["user_id"].as_str().unwrap(),
            user_id.to_string().as_str()
        );
    }

    pub async fn test_protected_route_without_token_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let req = Request::builder()
            .uri("/api/products")
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_session_info_with_valid_token_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/auth/session", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["expires_at"].as_str().is_some());
        assert_eq!(body["payment_sandbox"], true);
    }

    pub async fn test_logout_invalidates_token_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;

        let (status, body) = authed_post(
            router.clone(),
            "/api/auth/logout",
            &token,
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);

        let (status, _) = authed_get(router, "/api/auth/session", &token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_create_user_requires_key_sig_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let zero_sig = B64.encode([0u8; 64]);
        let (status, _) = authed_post(
            router,
            "/api/users",
            &token,
            serde_json::json!({
                "email": "newuser@example.com",
                "display_name": "New User",
                "role": "Support",
                "password": "pass123",
                "nonce": "nonce_that_was_never_issued",
                "signature": zero_sig
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_cannot_deactivate_self_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let owner1_id = create_owner_user(&s, "owner1@example.com", "pass1").await;
        create_owner_user(&s, "owner2@example.com", "pass2").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "owner1@example.com", "pass1").await;
        let (nonce, sig) = get_nonce_and_sig(&router, &state, &key).await;
        let (status, body) = authed_post(
            router,
            &format!("/api/users/{owner1_id}/deactivate"),
            &token,
            serde_json::json!({"nonce": nonce, "signature": sig}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "expected 409, got: {body}");
        assert_eq!(body["error"], "cannot_deactivate_self");
    }

    pub async fn test_cannot_deactivate_last_owner_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let owner_id = create_owner_user(&s, "owner@example.com", "pass1").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (nonce, sig) = get_nonce_and_sig(&router, &state, &key).await;
        let (status, body) = authed_post(
            router,
            &format!("/api/users/{owner_id}/deactivate"),
            &token,
            serde_json::json!({"nonce": nonce, "signature": sig}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "expected 409, got: {body}");
        assert_eq!(body["error"], "cannot_deactivate_last_owner");
    }

    pub async fn test_cannot_downgrade_last_owner_role_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let owner_id = create_owner_user(&s, "owner@example.com", "pass1").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (nonce, sig) = get_nonce_and_sig(&router, &state, &key).await;
        let (status, body) = authed_patch(
            router,
            &format!("/api/users/{owner_id}"),
            &token,
            serde_json::json!({"role": "Admin", "nonce": nonce, "signature": sig}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "expected 409, got: {body}");
        assert_eq!(body["error"], "cannot_downgrade_last_owner");
    }

    pub async fn test_change_own_password_succeeds_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_owner_user(&s, "owner@example.com", "oldpass").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "owner@example.com", "oldpass").await;
        let (status, body) = authed_post(
            router.clone(),
            "/api/users/me/password",
            &token,
            serde_json::json!({"current_password": "oldpass", "new_password": "newpass"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "change password failed: {body}");
        assert_eq!(body["ok"], true);

        let (status, _) = json_post(
            router.clone(),
            "/api/auth/login",
            serde_json::json!({"email": "owner@example.com", "password": "oldpass"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = json_post(
            router,
            "/api/auth/login",
            serde_json::json!({"email": "owner@example.com", "password": "newpass"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "login with new password failed: {body}"
        );
    }

    pub async fn test_rbac_admin_cannot_manage_users_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_user_with_role(&s, Role::Admin, "admin@example.com", "pass123").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "admin@example.com", "pass123").await;
        let (status, body) = authed_get(router, "/api/users", &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {body}");
    }

    pub async fn test_rbac_auditor_can_read_audit_log_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_user_with_role(&s, Role::Auditor, "auditor@example.com", "pass123").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "auditor@example.com", "pass123").await;
        let (status, body) = authed_get(router, "/api/audit-log", &token).await;
        assert_eq!(status, StatusCode::OK, "expected 200, got: {body}");
        assert!(body["items"].is_array());
    }

    pub async fn test_rbac_support_cannot_read_audit_log_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_user_with_role(&s, Role::Support, "support@example.com", "pass123").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "support@example.com", "pass123").await;
        let (status, body) = authed_get(router, "/api/audit-log", &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {body}");
    }

    pub async fn test_rbac_auditor_cannot_revoke_license_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        create_user_with_role(&s, Role::Auditor, "auditor@example.com", "pass123").await;
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "auditor@example.com", "pass123").await;
        let fake_license_id = Uuid::new_v4();
        let (status, body) = authed_post(
            router,
            &format!("/api/licenses/{fake_license_id}/revoke"),
            &token,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {body}");
    }

    pub async fn test_list_products_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/products", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["products"].is_array());
        assert_eq!(body["products"].as_array().unwrap().len(), 0);
    }

    pub async fn test_create_and_get_product_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;

        let (status, body) = authed_post(
            router.clone(),
            "/api/products",
            &token,
            serde_json::json!({
                "name": "Integration Test Product",
                "description": "Test description",
                "connectivity_mode": "Online",
                "seat_count": 5,
                "expiry_policy": "1y"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create failed: {body}");
        let id = body["id"].as_str().unwrap().to_owned();

        let (status, body) = authed_get(router, &format!("/api/products/{id}"), &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], id);
        assert_eq!(body["name"], "Integration Test Product");
    }

    pub async fn test_vendor_not_configured_returns_404_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, _) = authed_get(router, "/api/vendor", &token).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    pub async fn test_vendor_configured_returns_200_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        s.upsert_vendor_config(&VendorConfig {
            id: 1,
            public_key: vec![0u8; 32],
            public_key_fingerprint: "fp-test".to_owned(),
            registered_at: 1_000_000_000,
            rotated_from_key: None,
            rotated_at: None,
        })
        .await
        .unwrap();

        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/vendor", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["public_key_hex"].as_str().is_some());
        assert_eq!(body["payment_sandbox"], true);
    }

    pub async fn test_list_customers_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/customers", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["items"].is_array());
    }

    pub async fn test_list_licenses_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/licenses", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["items"].is_array());
    }

    pub async fn test_list_transfers_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/transfers", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["items"].is_array());
    }

    pub async fn test_list_security_events_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/security-events", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["items"].is_array());
    }

    pub async fn test_audit_log_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/audit-log", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["items"].is_array());
    }

    pub async fn test_unknown_route_returns_404_json_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let req = Request::builder()
            .uri("/api/xyzzy-does-not-exist")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(router, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }

    pub async fn test_post_without_content_type_returns_415_json_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .body(Body::from(r#"{"email":"x@example.com","password":"pass"}"#))
            .unwrap();
        let (status, body) = call(router, req).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(body["error"], "unsupported_media_type");
    }

    pub async fn test_invalid_json_returns_400_json_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("Content-Type", "application/json")
            .body(Body::from("not-json-at-all{{{"))
            .unwrap();
        let (status, body) = call(router, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_json");
    }

    pub async fn test_json_missing_fields_returns_422_json_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, body) = call(router, req).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], "unprocessable_entity");
    }

    pub async fn test_invalid_path_param_returns_400_json_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key);
        let router = build_router(state);
        let req = Request::builder()
            .uri("/api/customers/not-a-uuid")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(router, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_path_parameter");
    }
}

#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
mod sqlite_fns {
    use std::sync::Arc;
    use zlicenser_server::storage::SqliteStorage;

    pub async fn test_challenge_returns_nonce() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_challenge_returns_nonce_with(s).await;
    }

    pub async fn test_challenge_nonces_are_unique() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_challenge_nonces_are_unique_with(s).await;
    }

    pub async fn test_verify_with_valid_key_returns_token() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_verify_with_valid_key_returns_token_with(s).await;
    }

    pub async fn test_verify_with_invalid_sig_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_verify_with_invalid_sig_returns_401_with(s).await;
    }

    pub async fn test_verify_with_wrong_key_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_verify_with_wrong_key_returns_401_with(s).await;
    }

    pub async fn test_login_unknown_user_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_unknown_user_returns_401_with(s).await;
    }

    pub async fn test_login_correct_password_returns_token() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_correct_password_returns_token_with(s).await;
    }

    pub async fn test_login_wrong_password_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_wrong_password_returns_401_with(s).await;
    }

    pub async fn test_login_deactivated_user_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_deactivated_user_returns_401_with(s).await;
    }

    pub async fn test_key_session_has_owner_role() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_key_session_has_owner_role_with(s).await;
    }

    pub async fn test_password_session_has_correct_role() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_password_session_has_correct_role_with(s).await;
    }

    pub async fn test_session_info_includes_role_and_user_id() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_session_info_includes_role_and_user_id_with(s).await;
    }

    pub async fn test_protected_route_without_token_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_protected_route_without_token_returns_401_with(s).await;
    }

    pub async fn test_session_info_with_valid_token() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_session_info_with_valid_token_with(s).await;
    }

    pub async fn test_logout_invalidates_token() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_logout_invalidates_token_with(s).await;
    }

    pub async fn test_create_user_requires_key_sig() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_create_user_requires_key_sig_with(s).await;
    }

    pub async fn test_cannot_deactivate_self() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_cannot_deactivate_self_with(s).await;
    }

    pub async fn test_cannot_deactivate_last_owner() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_cannot_deactivate_last_owner_with(s).await;
    }

    pub async fn test_cannot_downgrade_last_owner_role() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_cannot_downgrade_last_owner_role_with(s).await;
    }

    pub async fn test_change_own_password_succeeds() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_change_own_password_succeeds_with(s).await;
    }

    pub async fn test_rbac_admin_cannot_manage_users() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_rbac_admin_cannot_manage_users_with(s).await;
    }

    pub async fn test_rbac_auditor_can_read_audit_log() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_rbac_auditor_can_read_audit_log_with(s).await;
    }

    pub async fn test_rbac_support_cannot_read_audit_log() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_rbac_support_cannot_read_audit_log_with(s).await;
    }

    pub async fn test_rbac_auditor_cannot_revoke_license() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_rbac_auditor_cannot_revoke_license_with(s).await;
    }

    pub async fn test_list_products_returns_empty_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_list_products_returns_empty_ok_with(s).await;
    }

    pub async fn test_create_and_get_product() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_create_and_get_product_with(s).await;
    }

    pub async fn test_vendor_not_configured_returns_404() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_vendor_not_configured_returns_404_with(s).await;
    }

    pub async fn test_vendor_configured_returns_200() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_vendor_configured_returns_200_with(s).await;
    }

    pub async fn test_list_customers_returns_empty_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_list_customers_returns_empty_ok_with(s).await;
    }

    pub async fn test_list_licenses_returns_empty_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_list_licenses_returns_empty_ok_with(s).await;
    }

    pub async fn test_list_transfers_returns_empty_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_list_transfers_returns_empty_ok_with(s).await;
    }

    pub async fn test_list_security_events_returns_empty_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_list_security_events_returns_empty_ok_with(s).await;
    }

    pub async fn test_audit_log_returns_empty_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_audit_log_returns_empty_ok_with(s).await;
    }

    pub async fn test_unknown_route_returns_404_json() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_unknown_route_returns_404_json_with(s).await;
    }

    pub async fn test_post_without_content_type_returns_415_json() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_post_without_content_type_returns_415_json_with(s).await;
    }

    pub async fn test_invalid_json_returns_400_json() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_invalid_json_returns_400_json_with(s).await;
    }

    pub async fn test_json_missing_fields_returns_422_json() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_json_missing_fields_returns_422_json_with(s).await;
    }

    pub async fn test_invalid_path_param_returns_400_json() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_invalid_path_param_returns_400_json_with(s).await;
    }
}
