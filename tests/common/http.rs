#![allow(dead_code)]

// Re-export SQLite-flavored wrappers so http_sqlite.rs can call them by their original names.
#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
#[allow(unused_imports)]
pub use sqlite_fns::*;


// Storage-agnostic HTTP test infrastructure
#[cfg(feature = "http-server")]
pub mod with_storage {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use zlicenser_server::{
        Error,
        http::{
            health::{HealthState, health_handler},
            product_info::{ProductInfoState, product_info_handler},
        },
        storage::{
            CustomerStore, EnrollmentStore, LicenseStore, PaymentStore, SeatStore, SecurityStore,
            Storage, VendorStore, types::*,
        },
    };

    // Broken storage: only get_vendor_config fails; everything else panics
    #[derive(Clone)]
    pub(crate) struct BrokenDb;

    #[async_trait]
    impl VendorStore for BrokenDb {
        async fn get_vendor_config(&self) -> zlicenser_server::Result<Option<VendorConfig>> {
            Err(Error::Database("simulated db failure".into()))
        }
        async fn upsert_vendor_config(&self, _: &VendorConfig) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn rotate_vendor_key(
            &self,
            _: &[u8],
            _: &str,
            _: &[u8],
            _: i64,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_product(&self, _: &Product) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_product(&self, _: Uuid) -> zlicenser_server::Result<Option<Product>> {
            unimplemented!()
        }
        async fn list_products(&self) -> zlicenser_server::Result<Vec<Product>> {
            unimplemented!()
        }
        async fn update_product(&self, _: &Product) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn upsert_term_declaration(
            &self,
            _: &ProductTermDeclaration,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_term_declaration(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<ProductTermDeclaration>> {
            unimplemented!()
        }
        async fn create_terms_document(
            &self,
            _: &ProductTermsDocument,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_terms_document(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<ProductTermsDocument>> {
            unimplemented!()
        }
        async fn get_active_terms_document(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<ProductTermsDocument>> {
            unimplemented!()
        }
        async fn list_terms_documents(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<ProductTermsDocument>> {
            unimplemented!()
        }
        async fn update_terms_document_validation(
            &self,
            _: Uuid,
            _: TermsValidationStatus,
            _: &str,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn acknowledge_terms_findings(
            &self,
            _: Uuid,
            _: i64,
            _: &str,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn activate_terms_document(&self, _: Uuid, _: i64) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn replace_customer_fields(
            &self,
            _: Uuid,
            _: &[ProductCustomerField],
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_customer_fields(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<ProductCustomerField>> {
            unimplemented!()
        }
        async fn create_upgrade_policy(
            &self,
            _: &UpgradePolicyRow,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_upgrade_policy(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<UpgradePolicyRow>> {
            unimplemented!()
        }
        async fn find_upgrade_policy(
            &self,
            _: Uuid,
            _: &str,
            _: &str,
        ) -> zlicenser_server::Result<Option<UpgradePolicyRow>> {
            unimplemented!()
        }
        async fn list_upgrade_policies(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<UpgradePolicyRow>> {
            unimplemented!()
        }
        async fn delete_upgrade_policy(&self, _: Uuid) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl CustomerStore for BrokenDb {
        async fn create_customer(&self, _: &Customer) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_customer(&self, _: Uuid) -> zlicenser_server::Result<Option<Customer>> {
            unimplemented!()
        }
        async fn find_customer_by_email(
            &self,
            _: Uuid,
            _: &str,
        ) -> zlicenser_server::Result<Option<Customer>> {
            unimplemented!()
        }
        async fn update_customer(&self, _: &Customer) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl LicenseStore for BrokenDb {
        async fn create_license(&self, _: &License) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_license(&self, _: Uuid) -> zlicenser_server::Result<Option<License>> {
            unimplemented!()
        }
        async fn list_licenses_for_customer(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<License>> {
            unimplemented!()
        }
        async fn update_license_status(
            &self,
            _: Uuid,
            _: LicenseStatus,
            _: Option<i64>,
            _: Option<&str>,
            _: Option<Uuid>,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn update_license_email_sent(&self, _: Uuid, _: i64) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_consent_record(&self, _: &ConsentRecord) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_consent_record(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<ConsentRecord>> {
            unimplemented!()
        }
        async fn get_consent_records_for_license(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<ConsentRecord>> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SeatStore for BrokenDb {
        async fn create_seat_binding(
            &self,
            _: &FingerprintSeatBinding,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_seat_binding(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<FingerprintSeatBinding>> {
            unimplemented!()
        }
        async fn find_seat_binding_by_commitment(
            &self,
            _: Uuid,
            _: &[u8],
        ) -> zlicenser_server::Result<Option<FingerprintSeatBinding>> {
            unimplemented!()
        }
        async fn list_seat_bindings(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<FingerprintSeatBinding>> {
            unimplemented!()
        }
        async fn count_active_seat_bindings(&self, _: Uuid) -> zlicenser_server::Result<u32> {
            unimplemented!()
        }
        async fn revoke_seat_binding(&self, _: Uuid, _: i64) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn update_seat_binding_verified(
            &self,
            _: Uuid,
            _: i64,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_issuance_secret(&self, _: &IssuanceSecret) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_issuance_secret(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<IssuanceSecret>> {
            unimplemented!()
        }
        async fn delete_issuance_secret(&self, _: Uuid) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_session(&self, _: &ActiveSession) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_session(&self, _: Uuid) -> zlicenser_server::Result<Option<ActiveSession>> {
            unimplemented!()
        }
        async fn get_active_or_suspect_session_for_binding(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<ActiveSession>> {
            unimplemented!()
        }
        async fn update_active_session(
            &self,
            _: Uuid,
            _: i64,
            _: ActiveSessionUpdate,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn expire_sessions_before(&self, _: i64) -> zlicenser_server::Result<u64> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl PaymentStore for BrokenDb {
        async fn create_payment_transaction(
            &self,
            _: &PaymentTransaction,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_payment_transaction(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<PaymentTransaction>> {
            unimplemented!()
        }
        async fn get_payment_transaction_for_license(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<PaymentTransaction>> {
            unimplemented!()
        }
        async fn update_payment_status(
            &self,
            _: Uuid,
            _: PaymentStatus,
            _: Option<i64>,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_transfer_request(
            &self,
            _: &TransferRequest,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_transfer_request(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<TransferRequest>> {
            unimplemented!()
        }
        async fn list_transfer_requests_for_license(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<TransferRequest>> {
            unimplemented!()
        }
        async fn resolve_transfer_request(
            &self,
            _: Uuid,
            _: TransferStatus,
            _: Option<&str>,
            _: i64,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl SecurityStore for BrokenDb {
        async fn create_quarantine_case(&self, _: &QuarantineCase) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_quarantine_case(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<QuarantineCase>> {
            unimplemented!()
        }
        async fn get_quarantine_case_by_case_id(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<QuarantineCase>> {
            unimplemented!()
        }
        async fn resume_quarantine_case(&self, _: Uuid, _: i64) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_active_quarantine_case_for_session(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<QuarantineCase>> {
            unimplemented!()
        }
        async fn get_active_quarantine_case_for_binding(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<QuarantineCase>> {
            unimplemented!()
        }
        async fn create_security_event(
            &self,
            _: &SecurityEventRecord,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_security_event_by_event_id(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<SecurityEventRecord>> {
            unimplemented!()
        }
        async fn get_security_events_for_license(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<SecurityEventRecord>> {
            unimplemented!()
        }
        async fn mark_security_event_reviewed(
            &self,
            _: i64,
            _: i64,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_revocation_record(
            &self,
            _: &RevocationRecord,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_revocation_record(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<RevocationRecord>> {
            unimplemented!()
        }
        async fn create_email_log_entry(&self, _: &EmailLogEntry) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn list_email_log_for_license(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Vec<EmailLogEntry>> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl EnrollmentStore for BrokenDb {
        async fn count_transferable_seat_bindings(&self, _: Uuid) -> zlicenser_server::Result<u32> {
            unimplemented!()
        }
        async fn set_seat_binding_transfer_pending(
            &self,
            _: Uuid,
            _: Option<i64>,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn create_enrollment_session(
            &self,
            _: &EnrollmentSession,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn get_enrollment_session(
            &self,
            _: Uuid,
        ) -> zlicenser_server::Result<Option<EnrollmentSession>> {
            unimplemented!()
        }
        async fn get_session_by_payment_intent(
            &self,
            _: &str,
        ) -> zlicenser_server::Result<Option<EnrollmentSession>> {
            unimplemented!()
        }
        async fn update_enrollment_session(
            &self,
            _: Uuid,
            _: i64,
            _: EnrollmentSessionUpdate,
        ) -> zlicenser_server::Result<()> {
            unimplemented!()
        }
        async fn list_grant_ready_sessions(
            &self,
        ) -> zlicenser_server::Result<Vec<EnrollmentSession>> {
            unimplemented!()
        }
    }

    // Router builders
    pub fn health_router<S>(storage: Arc<S>) -> Router
    where
        S: Storage + Clone + Send + Sync + 'static,
    {
        Router::new()
            .route("/health", get(health_handler::<S>))
            .with_state(HealthState {
                storage,
                version: "test-0.0.0",
            })
    }

    pub fn product_router<S>(storage: Arc<S>) -> Router
    where
        S: Storage + Clone + Send + Sync + 'static,
    {
        Router::new()
            .route("/products/{id}/info", get(product_info_handler::<S>))
            .with_state(ProductInfoState { storage })
    }

    pub async fn call(router: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    // Generic test functions (accept an already-created storage)
    pub async fn test_health_200_ok_with<S: Storage + Clone + Send + Sync + 'static>(s: Arc<S>) {
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(health_router(s), req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["database"], "ok");
        assert_eq!(body["test_mode"], false);
        assert!(!body["version"].is_null());
    }

    pub async fn test_health_503_db_error() {
        let s = Arc::new(BrokenDb);
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(health_router(s), req).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "error");
        assert_eq!(body["database"], "error");
    }

    pub async fn test_product_info_active_200_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let pid = Uuid::new_v4();
        s.create_product(&super::super::make_product(pid))
            .await
            .unwrap();
        let req = Request::builder()
            .uri(&format!("/products/{pid}/info"))
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(product_router(Arc::clone(&s)), req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], pid.to_string());
        assert_eq!(body["name"], "Test Product");
        assert!(body["terms_summary"].is_null());
    }

    pub async fn test_product_info_inactive_404_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let pid = Uuid::new_v4();
        let mut p = super::super::make_product(pid);
        p.active = false;
        s.create_product(&p).await.unwrap();
        let req = Request::builder()
            .uri(&format!("/products/{pid}/info"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(product_router(Arc::clone(&s)), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    pub async fn test_product_info_missing_404_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let pid = Uuid::new_v4();
        let req = Request::builder()
            .uri(&format!("/products/{pid}/info"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(product_router(s), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    pub async fn test_product_info_terms_present_with<
        S: Storage + Clone + Send + Sync + 'static,
    >(
        s: Arc<S>,
    ) {
        let pid = Uuid::new_v4();
        s.create_product(&super::super::make_product(pid))
            .await
            .unwrap();
        s.upsert_term_declaration(&super::super::make_valid_term_declaration(pid))
            .await
            .unwrap();
        let req = Request::builder()
            .uri(&format!("/products/{pid}/info"))
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(product_router(Arc::clone(&s)), req).await;
        assert_eq!(status, StatusCode::OK);
        let terms = &body["terms_summary"];
        assert!(!terms.is_null(), "terms_summary must be present");
        assert_eq!(terms["warranty"], "Days30");
        assert_eq!(terms["support_available"], true);
        assert_eq!(terms["updates_policy"], "Perpetual");
    }

    pub async fn test_product_info_terms_absent_with<S: Storage + Clone + Send + Sync + 'static>(
        s: Arc<S>,
    ) {
        let pid = Uuid::new_v4();
        s.create_product(&super::super::make_product(pid))
            .await
            .unwrap();
        let req = Request::builder()
            .uri(&format!("/products/{pid}/info"))
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(product_router(Arc::clone(&s)), req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["terms_summary"].is_null(),
            "terms_summary must be null when absent"
        );
    }
}


// SQLite thin wrappers, keep original names so http_sqlite.rs is unchanged
#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
mod sqlite_fns {
    use std::sync::Arc;

    use zlicenser_server::storage::SqliteStorage;

    pub async fn test_health_200_ok() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_health_200_ok_with(s).await;
    }

    pub async fn test_health_503_db_error() {
        super::with_storage::test_health_503_db_error().await;
    }

    pub async fn test_product_info_active_200() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_product_info_active_200_with(s).await;
    }

    pub async fn test_product_info_inactive_404() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_product_info_inactive_404_with(s).await;
    }

    pub async fn test_product_info_missing_404() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_product_info_missing_404_with(s).await;
    }

    pub async fn test_product_info_terms_present() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_product_info_terms_present_with(s).await;
    }

    pub async fn test_product_info_terms_absent() {
        let s = Arc::new(SqliteStorage::in_memory().await.unwrap());
        super::with_storage::test_product_info_terms_absent_with(s).await;
    }
}
