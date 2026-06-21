#![allow(dead_code)]

#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
#[allow(unused_imports)]
pub use sqlite_fns::*;

#[cfg(feature = "http-server")]
pub mod with_storage {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use tower::ServiceExt as _;

    use zlicenser_server::{
        http::dashboard::{
            build_dashboard_challenge_router, build_dashboard_login_verify_router,
            build_dashboard_router, state::DashboardState,
        },
        storage::{Storage, VendorConfig},
    };

    pub fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    pub fn make_state<S: Storage + Clone + Send + Sync + 'static>(
        storage: Arc<S>,
        signing_key: &SigningKey,
        password_hash: Option<String>,
    ) -> Arc<DashboardState<S>> {
        DashboardState::new(storage, signing_key.verifying_key(), true, password_hash)
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
        let _ = state; // state is unused here; nonce comes from the response
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
        password: &str,
    ) -> String {
        let (status, body) = json_post(
            router.clone(),
            "/api/auth/login",
            serde_json::json!({"password": password}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "login failed: {body}");
        body["token"].as_str().unwrap().to_owned()
    }

    pub async fn test_challenge_returns_nonce_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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

    pub async fn test_login_no_password_configured_returns_403_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key, None);
        let router = build_router(state);
        let (status, _) = json_post(
            router,
            "/api/auth/login",
            serde_json::json!({"password": "anything"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    pub async fn test_login_correct_password_returns_token_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let hash = bcrypt::hash("testpass", bcrypt::DEFAULT_COST).unwrap();
        let state = make_state(Arc::clone(&s), &key, Some(hash));
        let router = build_router(Arc::clone(&state));
        let token = get_password_token(&router, &state, "testpass").await;
        assert!(!token.is_empty());
    }

    pub async fn test_login_wrong_password_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let hash = bcrypt::hash("testpass", bcrypt::DEFAULT_COST).unwrap();
        let state = make_state(Arc::clone(&s), &key, Some(hash));
        let router = build_router(state);
        let (status, _) = json_post(
            router,
            "/api/auth/login",
            serde_json::json!({"password": "wrongpass"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    pub async fn test_protected_route_without_token_returns_401_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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

    pub async fn test_list_products_returns_empty_ok_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let key = make_signing_key();
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
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
        let state = make_state(Arc::clone(&s), &key, None);
        let router = build_router(Arc::clone(&state));
        let token = get_key_token(&router, &state, &key).await;
        let (status, body) = authed_get(router, "/api/audit-log", &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["items"].is_array());
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

    pub async fn test_login_no_password_configured_returns_403() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_no_password_configured_returns_403_with(s).await;
    }

    pub async fn test_login_correct_password_returns_token() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_correct_password_returns_token_with(s).await;
    }

    pub async fn test_login_wrong_password_returns_401() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_login_wrong_password_returns_401_with(s).await;
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
}
