pub mod types;
pub use types::*;

#[cfg(feature = "storage-sqlite")]
pub mod sqlite;
#[cfg(feature = "storage-sqlite")]
pub use sqlite::SqliteStorage;

#[cfg(feature = "storage-postgres")]
pub mod postgres;
#[cfg(feature = "storage-postgres")]
pub use postgres::PostgresStorage;

use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait VendorStore: Send + Sync {
    async fn get_vendor_config(&self) -> crate::Result<Option<VendorConfig>>;
    async fn upsert_vendor_config(&self, config: &VendorConfig) -> crate::Result<()>;
    async fn rotate_vendor_key(
        &self,
        new_public_key: &[u8],
        new_fingerprint: &str,
        rotated_from: &[u8],
        rotated_at: i64,
    ) -> crate::Result<()>;

    async fn create_product(&self, p: &Product) -> crate::Result<()>;
    async fn get_product(&self, id: Uuid) -> crate::Result<Option<Product>>;
    async fn list_products(&self) -> crate::Result<Vec<Product>>;
    async fn update_product(&self, p: &Product) -> crate::Result<()>;

    async fn upsert_term_declaration(&self, d: &ProductTermDeclaration) -> crate::Result<()>;
    async fn get_term_declaration(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Option<ProductTermDeclaration>>;

    async fn create_terms_document(&self, d: &ProductTermsDocument) -> crate::Result<()>;
    async fn get_terms_document(&self, id: Uuid) -> crate::Result<Option<ProductTermsDocument>>;
    async fn get_active_terms_document(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Option<ProductTermsDocument>>;
    async fn list_terms_documents(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Vec<ProductTermsDocument>>;
    async fn update_terms_document_validation(
        &self,
        id: Uuid,
        status: TermsValidationStatus,
        findings: &str,
    ) -> crate::Result<()>;
    async fn acknowledge_terms_findings(
        &self,
        id: Uuid,
        acknowledged_at: i64,
        findings: &str,
    ) -> crate::Result<()>;
    async fn activate_terms_document(&self, id: Uuid, activated_at: i64) -> crate::Result<()>;

    async fn replace_customer_fields(
        &self,
        product_id: Uuid,
        fields: &[ProductCustomerField],
    ) -> crate::Result<()>;
    async fn get_customer_fields(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Vec<ProductCustomerField>>;

    async fn create_upgrade_policy(&self, p: &UpgradePolicyRow) -> crate::Result<()>;
    async fn get_upgrade_policy(&self, id: Uuid) -> crate::Result<Option<UpgradePolicyRow>>;
    async fn find_upgrade_policy(
        &self,
        product_id: Uuid,
        from_version: &str,
        to_version: &str,
    ) -> crate::Result<Option<UpgradePolicyRow>>;
    async fn list_upgrade_policies(&self, product_id: Uuid)
        -> crate::Result<Vec<UpgradePolicyRow>>;
    async fn delete_upgrade_policy(&self, id: Uuid) -> crate::Result<()>;
}

#[async_trait]
pub trait CustomerStore: Send + Sync {
    async fn create_customer(&self, c: &Customer) -> crate::Result<()>;
    async fn get_customer(&self, id: Uuid) -> crate::Result<Option<Customer>>;
    async fn find_customer_by_email(
        &self,
        product_id: Uuid,
        email: &str,
    ) -> crate::Result<Option<Customer>>;
    async fn update_customer(&self, c: &Customer) -> crate::Result<()>;
}

#[async_trait]
pub trait LicenseStore: Send + Sync {
    async fn create_license(&self, l: &License) -> crate::Result<()>;
    async fn get_license(&self, id: Uuid) -> crate::Result<Option<License>>;
    async fn list_licenses_for_customer(&self, customer_id: Uuid) -> crate::Result<Vec<License>>;
    async fn update_license_status(
        &self,
        id: Uuid,
        status: LicenseStatus,
        revoked_at: Option<i64>,
        revocation_reason: Option<&str>,
        superseded_by: Option<Uuid>,
    ) -> crate::Result<()>;
    async fn update_license_email_sent(&self, id: Uuid, sent_at: i64) -> crate::Result<()>;

    async fn create_consent_record(&self, r: &ConsentRecord) -> crate::Result<()>;
    async fn get_consent_record(&self, id: Uuid) -> crate::Result<Option<ConsentRecord>>;
    async fn get_consent_records_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<ConsentRecord>>;
}

#[async_trait]
pub trait SeatStore: Send + Sync {
    async fn create_seat_binding(&self, b: &FingerprintSeatBinding) -> crate::Result<()>;
    async fn get_seat_binding(&self, id: Uuid) -> crate::Result<Option<FingerprintSeatBinding>>;
    async fn find_seat_binding_by_commitment(
        &self,
        license_id: Uuid,
        commitment: &[u8],
    ) -> crate::Result<Option<FingerprintSeatBinding>>;
    async fn list_seat_bindings(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<FingerprintSeatBinding>>;
    async fn count_active_seat_bindings(&self, license_id: Uuid) -> crate::Result<u32>;
    async fn revoke_seat_binding(&self, id: Uuid, revoked_at: i64) -> crate::Result<()>;
    async fn update_seat_binding_verified(&self, id: Uuid, verified_at: i64) -> crate::Result<()>;

    async fn create_issuance_secret(&self, s: &IssuanceSecret) -> crate::Result<()>;
    async fn get_issuance_secret(&self, license_id: Uuid) -> crate::Result<Option<IssuanceSecret>>;
    async fn delete_issuance_secret(&self, license_id: Uuid) -> crate::Result<()>;

    async fn create_session(&self, s: &ActiveSession) -> crate::Result<()>;
    async fn get_session(&self, id: Uuid) -> crate::Result<Option<ActiveSession>>;
    async fn get_active_session_for_binding(
        &self,
        binding_id: Uuid,
    ) -> crate::Result<Option<ActiveSession>>;
    async fn update_session_heartbeat(
        &self,
        id: Uuid,
        heartbeat_at: i64,
        seq_no: i64,
    ) -> crate::Result<()>;
    async fn update_session_status(&self, id: Uuid, status: SessionStatus) -> crate::Result<()>;
    async fn expire_sessions_before(&self, expires_at: i64) -> crate::Result<u64>;
}

#[async_trait]
pub trait PaymentStore: Send + Sync {
    async fn create_payment_transaction(&self, t: &PaymentTransaction) -> crate::Result<()>;
    async fn get_payment_transaction(&self, id: Uuid) -> crate::Result<Option<PaymentTransaction>>;
    async fn get_payment_transaction_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Option<PaymentTransaction>>;
    async fn update_payment_status(
        &self,
        id: Uuid,
        status: PaymentStatus,
        confirmed_at: Option<i64>,
    ) -> crate::Result<()>;

    async fn create_transfer_request(&self, r: &TransferRequest) -> crate::Result<()>;
    async fn get_transfer_request(&self, id: Uuid) -> crate::Result<Option<TransferRequest>>;
    async fn list_transfer_requests_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<TransferRequest>>;
    async fn resolve_transfer_request(
        &self,
        id: Uuid,
        status: TransferStatus,
        vendor_note: Option<&str>,
        resolved_at: i64,
    ) -> crate::Result<()>;
}

#[async_trait]
pub trait SecurityStore: Send + Sync {
    async fn create_quarantine_case(&self, c: &QuarantineCase) -> crate::Result<()>;
    async fn get_quarantine_case(&self, id: Uuid) -> crate::Result<Option<QuarantineCase>>;
    async fn get_quarantine_case_by_case_id(
        &self,
        case_id: Uuid,
    ) -> crate::Result<Option<QuarantineCase>>;
    async fn resolve_quarantine_case(
        &self,
        id: Uuid,
        status: QuarantineStatus,
        resolution: Option<&str>,
        resolved_at: i64,
        vendor_note: Option<&str>,
    ) -> crate::Result<()>;

    async fn create_security_event(&self, e: &SecurityEvent) -> crate::Result<()>;
    async fn get_security_events_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<SecurityEvent>>;
    async fn mark_security_event_reviewed(
        &self,
        id: i64,
        reviewed_by: &str,
        reviewed_at: i64,
    ) -> crate::Result<()>;

    async fn create_revocation_record(&self, r: &RevocationRecord) -> crate::Result<()>;
    async fn get_revocation_record(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Option<RevocationRecord>>;

    async fn create_email_log_entry(&self, e: &EmailLogEntry) -> crate::Result<()>;
    async fn list_email_log_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<EmailLogEntry>>;
}

pub trait Storage:
    VendorStore + CustomerStore + LicenseStore + SeatStore + PaymentStore + SecurityStore
{
}

impl<T> Storage for T where
    T: VendorStore + CustomerStore + LicenseStore + SeatStore + PaymentStore + SecurityStore
{
}
