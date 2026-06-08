use async_trait::async_trait;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::str::FromStr;
use uuid::Uuid;

#[allow(clippy::wildcard_imports)] // storage impls use all domain types from this module
use crate::storage::types::*;
use crate::storage::{
    CustomerStore, EnrollmentStore, LicenseStore, PaymentStore, SeatStore, SecurityStore,
    VendorStore,
};

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(database_url: &str) -> crate::Result<Self> {
        let opts = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| crate::Error::Database(e.to_string()))?
            .pragma("foreign_keys", "ON")
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .connect_with(opts)
            .await
            .map_err(|e| crate::Error::Database(e.to_string()))?;

        sqlx::migrate!("migrations/sqlite")
            .run(&pool)
            .await
            .map_err(|e| crate::Error::Migration(e.to_string()))?;

        Ok(Self { pool })
    }

    pub async fn in_memory() -> crate::Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| crate::Error::Database(e.to_string()))?
            .pragma("foreign_keys", "ON");

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .map_err(|e| crate::Error::Database(e.to_string()))?;

        sqlx::migrate!("migrations/sqlite")
            .run(&pool)
            .await
            .map_err(|e| crate::Error::Migration(e.to_string()))?;

        Ok(Self { pool })
    }
}

fn uuid_to_blob(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

fn blob_to_uuid(b: &[u8]) -> crate::Result<Uuid> {
    Uuid::from_slice(b).map_err(|e| crate::Error::Corrupt(format!("invalid UUID bytes: {e}")))
}

fn bool_to_int(b: bool) -> i64 {
    i64::from(b)
}

fn int_to_bool(n: i64) -> bool {
    n != 0
}

fn encode_enum<T: std::fmt::Display>(t: &T) -> String {
    t.to_string()
}

fn decode_enum<T: std::str::FromStr<Err = crate::Error>>(s: impl AsRef<str>) -> crate::Result<T> {
    s.as_ref().parse()
}

fn decode_opt_uuid(b: Option<Vec<u8>>) -> crate::Result<Option<Uuid>> {
    b.map(|bytes| blob_to_uuid(&bytes)).transpose()
}

#[derive(sqlx::FromRow)]
struct DbVendorConfig {
    id: i64,
    public_key: Vec<u8>,
    public_key_fingerprint: String,
    registered_at: i64,
    rotated_from_key: Option<Vec<u8>>,
    rotated_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbProduct {
    id: Vec<u8>,
    name: String,
    description: String,
    connectivity_mode: String,
    seat_count: i64,
    expiry_policy: String,
    grace_period_days: Option<i64>,
    heartbeat_interval_secs: Option<i64>,
    heartbeat_grace_secs: Option<i64>,
    shutdown_countdown_secs: Option<i64>,
    tsa_tier: String,
    bundle_version: String,
    transfer_policy: String,
    pricing_amount: i64,
    pricing_currency: String,
    payment_provider: String,
    min_client_version_warning: Option<String>,
    min_client_version_required: Option<String>,
    active: i64,
    created_at: i64,
    updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbProductTermDeclaration {
    product_id: Vec<u8>,
    warranty: String,
    refund: String,
    revocation: String,
    expiry: String,
    support_available: i64,
    support_channels: String,
    response_sla_hours: Option<i64>,
    support_scope: Option<String>,
    support_coverage: Option<String>,
    updates_policy: String,
}

#[derive(sqlx::FromRow)]
struct DbProductTermsDocument {
    id: Vec<u8>,
    product_id: Vec<u8>,
    typst_source: String,
    rendered_hash: String,
    validation_status: String,
    validation_findings: String,
    vendor_acknowledged_at: Option<i64>,
    vendor_acknowledged_findings: Option<String>,
    activated_at: Option<i64>,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbProductCustomerField {
    id: Vec<u8>,
    product_id: Vec<u8>,
    field_key: String,
    required: i64,
    gdpr_basis: String,
    purpose_description: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbUpgradePolicy {
    id: Vec<u8>,
    product_id: Vec<u8>,
    from_version: String,
    to_version: String,
    policy: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbCustomer {
    id: Vec<u8>,
    product_id: Vec<u8>,
    full_name: String,
    email: String,
    field_values: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbConsentRecord {
    id: Vec<u8>,
    customer_id: Vec<u8>,
    license_id: Vec<u8>,
    terms_document_id: Vec<u8>,
    terms_rendered_hash: String,
    checkboxes_ticked: String,
    accepted_at_ns: i64,
    ip_address: String,
    client_version: String,
    protocol_version: i64,
    terms_findings_shown: String,
    payment_provider: String,
    payment_provider_tier: String,
}

#[derive(sqlx::FromRow)]
struct DbLicense {
    id: Vec<u8>,
    customer_id: Vec<u8>,
    product_id: Vec<u8>,
    bundle_version: String,
    connectivity_mode: String,
    seat_count: i64,
    expiry_at: Option<i64>,
    status: String,
    superseded_by: Option<Vec<u8>>,
    revoked_at: Option<i64>,
    revocation_reason: Option<String>,
    created_at: i64,
    email_sent_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbFingerprintSeatBinding {
    id: Vec<u8>,
    license_id: Vec<u8>,
    fingerprint_commitment: Vec<u8>,
    seat_index: i64,
    bound_at: i64,
    last_verified_at: Option<i64>,
    revoked_at: Option<i64>,
    transfer_pending_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbIssuanceSecret {
    license_id: Vec<u8>,
    secret: Vec<u8>,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbPaymentTransaction {
    id: Vec<u8>,
    license_id: Vec<u8>,
    provider: String,
    provider_transaction_id: String,
    amount: i64,
    currency: String,
    provider_tier: String,
    test_mode: i64,
    status: String,
    created_at: i64,
    confirmed_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbTransferRequest {
    id: Vec<u8>,
    license_id: Vec<u8>,
    old_fingerprint_commitment: Vec<u8>,
    new_fingerprint_commitment: Vec<u8>,
    requested_at: i64,
    status: String,
    vendor_note: Option<String>,
    resolved_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbActiveSession {
    id: Vec<u8>,
    binding_id: Vec<u8>,
    ephemeral_pubkey: Vec<u8>,
    issued_at: i64,
    expires_at: i64,
    last_heartbeat_at: Option<i64>,
    seq_no: i64,
    status: String,
}

#[derive(sqlx::FromRow)]
struct DbQuarantineCase {
    id: Vec<u8>,
    case_id: Vec<u8>,
    binding_id: Vec<u8>,
    session_id: Option<Vec<u8>>,
    trigger: String,
    triggered_at: i64,
    status: String,
    resolution: Option<String>,
    resolved_at: Option<i64>,
    vendor_note: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbSecurityEvent {
    id: i64,
    event_id: Vec<u8>,
    license_id: Vec<u8>,
    binding_id: Vec<u8>,
    session_id: Option<Vec<u8>>,
    occurred_at_ns: i64,
    received_at_ns: i64,
    event_type: String,
    severity: String,
    payload: String,
    response: String,
    reviewed_by: Option<String>,
    reviewed_at: Option<i64>,
    case_id: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct DbRevocationRecord {
    license_id: Vec<u8>,
    revoked_at: i64,
    revoked_by: String,
    reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbEmailLogEntry {
    id: Vec<u8>,
    license_id: Vec<u8>,
    email_type: String,
    sent_to: String,
    sent_at: i64,
    success: i64,
    error_message: Option<String>,
}

#[allow(clippy::unnecessary_wraps)] // consistent with other from_db_* functions that do need Result
fn from_db_vendor_config(r: DbVendorConfig) -> crate::Result<VendorConfig> {
    Ok(VendorConfig {
        id: r.id,
        public_key: r.public_key,
        public_key_fingerprint: r.public_key_fingerprint,
        registered_at: r.registered_at,
        rotated_from_key: r.rotated_from_key,
        rotated_at: r.rotated_at,
    })
}

fn from_db_product(r: DbProduct) -> crate::Result<Product> {
    Ok(Product {
        id: blob_to_uuid(&r.id)?,
        name: r.name,
        description: r.description,
        connectivity_mode: decode_enum(r.connectivity_mode)?,
        seat_count: r.seat_count,
        expiry_policy: r.expiry_policy,
        grace_period_days: r.grace_period_days,
        heartbeat_interval_secs: r.heartbeat_interval_secs,
        heartbeat_grace_secs: r.heartbeat_grace_secs,
        shutdown_countdown_secs: r.shutdown_countdown_secs,
        tsa_tier: decode_enum(r.tsa_tier)?,
        bundle_version: r.bundle_version,
        transfer_policy: decode_enum(r.transfer_policy)?,
        pricing_amount: r.pricing_amount,
        pricing_currency: r.pricing_currency,
        payment_provider: decode_enum(r.payment_provider)?,
        min_client_version_warning: r.min_client_version_warning,
        min_client_version_required: r.min_client_version_required,
        active: int_to_bool(r.active),
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

fn from_db_term_declaration(r: DbProductTermDeclaration) -> crate::Result<ProductTermDeclaration> {
    Ok(ProductTermDeclaration {
        product_id: blob_to_uuid(&r.product_id)?,
        warranty: r.warranty,
        refund: r.refund,
        revocation: r.revocation,
        expiry: r.expiry,
        support_available: int_to_bool(r.support_available),
        support_channels: r.support_channels,
        response_sla_hours: r.response_sla_hours,
        support_scope: r.support_scope,
        support_coverage: r.support_coverage,
        updates_policy: r.updates_policy,
    })
}

fn from_db_terms_document(r: DbProductTermsDocument) -> crate::Result<ProductTermsDocument> {
    Ok(ProductTermsDocument {
        id: blob_to_uuid(&r.id)?,
        product_id: blob_to_uuid(&r.product_id)?,
        typst_source: r.typst_source,
        rendered_hash: r.rendered_hash,
        validation_status: decode_enum(r.validation_status)?,
        validation_findings: r.validation_findings,
        vendor_acknowledged_at: r.vendor_acknowledged_at,
        vendor_acknowledged_findings: r.vendor_acknowledged_findings,
        activated_at: r.activated_at,
        created_at: r.created_at,
    })
}

fn from_db_customer_field(r: DbProductCustomerField) -> crate::Result<ProductCustomerField> {
    Ok(ProductCustomerField {
        id: blob_to_uuid(&r.id)?,
        product_id: blob_to_uuid(&r.product_id)?,
        field_key: r.field_key,
        required: int_to_bool(r.required),
        gdpr_basis: decode_enum(r.gdpr_basis)?,
        purpose_description: r.purpose_description,
    })
}

fn from_db_upgrade_policy(r: DbUpgradePolicy) -> crate::Result<UpgradePolicyRow> {
    Ok(UpgradePolicyRow {
        id: blob_to_uuid(&r.id)?,
        product_id: blob_to_uuid(&r.product_id)?,
        from_version: r.from_version,
        to_version: r.to_version,
        policy: decode_enum(r.policy)?,
        created_at: r.created_at,
    })
}

fn from_db_customer(r: DbCustomer) -> crate::Result<Customer> {
    Ok(Customer {
        id: blob_to_uuid(&r.id)?,
        product_id: blob_to_uuid(&r.product_id)?,
        full_name: r.full_name,
        email: r.email,
        field_values: r.field_values,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

fn from_db_consent_record(r: DbConsentRecord) -> crate::Result<ConsentRecord> {
    Ok(ConsentRecord {
        id: blob_to_uuid(&r.id)?,
        customer_id: blob_to_uuid(&r.customer_id)?,
        license_id: blob_to_uuid(&r.license_id)?,
        terms_document_id: blob_to_uuid(&r.terms_document_id)?,
        terms_rendered_hash: r.terms_rendered_hash,
        checkboxes_ticked: r.checkboxes_ticked,
        accepted_at_ns: r.accepted_at_ns,
        ip_address: r.ip_address,
        client_version: r.client_version,
        protocol_version: r.protocol_version,
        terms_findings_shown: r.terms_findings_shown,
        payment_provider: decode_enum(r.payment_provider)?,
        payment_provider_tier: decode_enum(r.payment_provider_tier)?,
    })
}

fn from_db_license(r: DbLicense) -> crate::Result<License> {
    Ok(License {
        id: blob_to_uuid(&r.id)?,
        customer_id: blob_to_uuid(&r.customer_id)?,
        product_id: blob_to_uuid(&r.product_id)?,
        bundle_version: r.bundle_version,
        connectivity_mode: decode_enum(r.connectivity_mode)?,
        seat_count: r.seat_count,
        expiry_at: r.expiry_at,
        status: decode_enum(r.status)?,
        superseded_by: decode_opt_uuid(r.superseded_by)?,
        revoked_at: r.revoked_at,
        revocation_reason: r.revocation_reason,
        created_at: r.created_at,
        email_sent_at: r.email_sent_at,
    })
}

fn from_db_seat_binding(r: DbFingerprintSeatBinding) -> crate::Result<FingerprintSeatBinding> {
    Ok(FingerprintSeatBinding {
        id: blob_to_uuid(&r.id)?,
        license_id: blob_to_uuid(&r.license_id)?,
        fingerprint_commitment: r.fingerprint_commitment,
        seat_index: r.seat_index,
        bound_at: r.bound_at,
        last_verified_at: r.last_verified_at,
        revoked_at: r.revoked_at,
        transfer_pending_at: r.transfer_pending_at,
    })
}

fn from_db_issuance_secret(r: DbIssuanceSecret) -> crate::Result<IssuanceSecret> {
    Ok(IssuanceSecret {
        license_id: blob_to_uuid(&r.license_id)?,
        secret: r.secret,
        created_at: r.created_at,
    })
}

fn from_db_payment_transaction(r: DbPaymentTransaction) -> crate::Result<PaymentTransaction> {
    Ok(PaymentTransaction {
        id: blob_to_uuid(&r.id)?,
        license_id: blob_to_uuid(&r.license_id)?,
        provider: decode_enum(r.provider)?,
        provider_transaction_id: r.provider_transaction_id,
        amount: r.amount,
        currency: r.currency,
        provider_tier: decode_enum(r.provider_tier)?,
        test_mode: int_to_bool(r.test_mode),
        status: decode_enum(r.status)?,
        created_at: r.created_at,
        confirmed_at: r.confirmed_at,
    })
}

fn from_db_transfer_request(r: DbTransferRequest) -> crate::Result<TransferRequest> {
    Ok(TransferRequest {
        id: blob_to_uuid(&r.id)?,
        license_id: blob_to_uuid(&r.license_id)?,
        old_fingerprint_commitment: r.old_fingerprint_commitment,
        new_fingerprint_commitment: r.new_fingerprint_commitment,
        requested_at: r.requested_at,
        status: decode_enum(r.status)?,
        vendor_note: r.vendor_note,
        resolved_at: r.resolved_at,
    })
}

fn from_db_active_session(r: DbActiveSession) -> crate::Result<ActiveSession> {
    Ok(ActiveSession {
        id: blob_to_uuid(&r.id)?,
        binding_id: blob_to_uuid(&r.binding_id)?,
        ephemeral_pubkey: r.ephemeral_pubkey,
        issued_at: r.issued_at,
        expires_at: r.expires_at,
        last_heartbeat_at: r.last_heartbeat_at,
        seq_no: r.seq_no,
        status: decode_enum(r.status)?,
    })
}

fn from_db_quarantine_case(r: DbQuarantineCase) -> crate::Result<QuarantineCase> {
    Ok(QuarantineCase {
        id: blob_to_uuid(&r.id)?,
        case_id: blob_to_uuid(&r.case_id)?,
        binding_id: blob_to_uuid(&r.binding_id)?,
        session_id: decode_opt_uuid(r.session_id)?,
        trigger: decode_enum(r.trigger)?,
        triggered_at: r.triggered_at,
        status: decode_enum(r.status)?,
        resolution: r.resolution,
        resolved_at: r.resolved_at,
        vendor_note: r.vendor_note,
    })
}

fn from_db_security_event(r: DbSecurityEvent) -> crate::Result<SecurityEvent> {
    Ok(SecurityEvent {
        id: r.id,
        event_id: blob_to_uuid(&r.event_id)?,
        license_id: blob_to_uuid(&r.license_id)?,
        binding_id: blob_to_uuid(&r.binding_id)?,
        session_id: decode_opt_uuid(r.session_id)?,
        occurred_at_ns: r.occurred_at_ns,
        received_at_ns: r.received_at_ns,
        event_type: r.event_type,
        severity: decode_enum(r.severity)?,
        payload: r.payload,
        response: decode_enum(r.response)?,
        reviewed_by: r.reviewed_by,
        reviewed_at: r.reviewed_at,
        case_id: decode_opt_uuid(r.case_id)?,
    })
}

fn from_db_revocation_record(r: DbRevocationRecord) -> crate::Result<RevocationRecord> {
    Ok(RevocationRecord {
        license_id: blob_to_uuid(&r.license_id)?,
        revoked_at: r.revoked_at,
        revoked_by: decode_enum(r.revoked_by)?,
        reason: r.reason,
    })
}

fn from_db_email_log_entry(r: DbEmailLogEntry) -> crate::Result<EmailLogEntry> {
    Ok(EmailLogEntry {
        id: blob_to_uuid(&r.id)?,
        license_id: blob_to_uuid(&r.license_id)?,
        email_type: decode_enum(r.email_type)?,
        sent_to: r.sent_to,
        sent_at: r.sent_at,
        success: int_to_bool(r.success),
        error_message: r.error_message,
    })
}

#[derive(sqlx::FromRow)]
struct DbEnrollmentSession {
    id: Vec<u8>,
    product_id: Vec<u8>,
    fingerprint_commitment: Vec<u8>,
    customer_pubkey: Vec<u8>,
    client_version: String,
    protocol_version: i64,
    state: String,
    offer_nonce: Option<Vec<u8>>,
    offer_expires_at: Option<i64>,
    terms_document_id: Option<Vec<u8>>,
    request_bytes: Vec<u8>,
    offer_bytes: Option<Vec<u8>>,
    receipt_bytes: Option<Vec<u8>>,
    payment_intent_id: Option<String>,
    payment_captured: i64,
    grant_bytes: Option<Vec<u8>>,
    transfer_request_id: Option<Vec<u8>>,
    license_id: Option<Vec<u8>>,
    abandon_reason: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn from_db_enrollment_session(r: DbEnrollmentSession) -> crate::Result<EnrollmentSession> {
    Ok(EnrollmentSession {
        id: blob_to_uuid(&r.id)?,
        product_id: blob_to_uuid(&r.product_id)?,
        fingerprint_commitment: r.fingerprint_commitment,
        customer_pubkey: r.customer_pubkey,
        client_version: r.client_version,
        protocol_version: r.protocol_version,
        state: decode_enum(r.state)?,
        offer_nonce: r.offer_nonce,
        offer_expires_at: r.offer_expires_at,
        terms_document_id: decode_opt_uuid(r.terms_document_id)?,
        request_bytes: r.request_bytes,
        offer_bytes: r.offer_bytes,
        receipt_bytes: r.receipt_bytes,
        payment_intent_id: r.payment_intent_id,
        payment_captured: int_to_bool(r.payment_captured),
        grant_bytes: r.grant_bytes,
        transfer_request_id: decode_opt_uuid(r.transfer_request_id)?,
        license_id: decode_opt_uuid(r.license_id)?,
        abandon_reason: r.abandon_reason,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

#[async_trait]
impl VendorStore for SqliteStorage {
    async fn get_vendor_config(&self) -> crate::Result<Option<VendorConfig>> {
        sqlx::query_as::<_, DbVendorConfig>("SELECT * FROM vendor_config WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_vendor_config)
            .transpose()
    }

    async fn upsert_vendor_config(&self, config: &VendorConfig) -> crate::Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO vendor_config \
             (id, public_key, public_key_fingerprint, registered_at, rotated_from_key, rotated_at) \
             VALUES (1, ?, ?, ?, ?, ?)",
        )
        .bind(&config.public_key)
        .bind(&config.public_key_fingerprint)
        .bind(config.registered_at)
        .bind(&config.rotated_from_key)
        .bind(config.rotated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn rotate_vendor_key(
        &self,
        new_public_key: &[u8],
        new_fingerprint: &str,
        rotated_from: &[u8],
        rotated_at: i64,
    ) -> crate::Result<()> {
        sqlx::query(
            "UPDATE vendor_config SET public_key = ?, public_key_fingerprint = ?, \
             rotated_from_key = ?, rotated_at = ? WHERE id = 1",
        )
        .bind(new_public_key)
        .bind(new_fingerprint)
        .bind(rotated_from)
        .bind(rotated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_product(&self, p: &Product) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO products \
             (id, name, description, connectivity_mode, seat_count, expiry_policy, \
              grace_period_days, heartbeat_interval_secs, heartbeat_grace_secs, \
              shutdown_countdown_secs, tsa_tier, bundle_version, transfer_policy, \
              pricing_amount, pricing_currency, payment_provider, \
              min_client_version_warning, min_client_version_required, \
              active, created_at, updated_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(p.id))
        .bind(&p.name)
        .bind(&p.description)
        .bind(encode_enum(&p.connectivity_mode))
        .bind(p.seat_count)
        .bind(&p.expiry_policy)
        .bind(p.grace_period_days)
        .bind(p.heartbeat_interval_secs)
        .bind(p.heartbeat_grace_secs)
        .bind(p.shutdown_countdown_secs)
        .bind(encode_enum(&p.tsa_tier))
        .bind(&p.bundle_version)
        .bind(encode_enum(&p.transfer_policy))
        .bind(p.pricing_amount)
        .bind(&p.pricing_currency)
        .bind(encode_enum(&p.payment_provider))
        .bind(&p.min_client_version_warning)
        .bind(&p.min_client_version_required)
        .bind(bool_to_int(p.active))
        .bind(p.created_at)
        .bind(p.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_product(&self, id: Uuid) -> crate::Result<Option<Product>> {
        sqlx::query_as::<_, DbProduct>("SELECT * FROM products WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_product)
            .transpose()
    }

    async fn list_products(&self) -> crate::Result<Vec<Product>> {
        sqlx::query_as::<_, DbProduct>("SELECT * FROM products ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(from_db_product)
            .collect()
    }

    async fn update_product(&self, p: &Product) -> crate::Result<()> {
        sqlx::query(
            "UPDATE products SET \
             name = ?, description = ?, connectivity_mode = ?, seat_count = ?, \
             expiry_policy = ?, grace_period_days = ?, heartbeat_interval_secs = ?, \
             heartbeat_grace_secs = ?, shutdown_countdown_secs = ?, tsa_tier = ?, \
             bundle_version = ?, transfer_policy = ?, pricing_amount = ?, \
             pricing_currency = ?, payment_provider = ?, min_client_version_warning = ?, \
             min_client_version_required = ?, active = ?, updated_at = ? \
             WHERE id = ?",
        )
        .bind(&p.name)
        .bind(&p.description)
        .bind(encode_enum(&p.connectivity_mode))
        .bind(p.seat_count)
        .bind(&p.expiry_policy)
        .bind(p.grace_period_days)
        .bind(p.heartbeat_interval_secs)
        .bind(p.heartbeat_grace_secs)
        .bind(p.shutdown_countdown_secs)
        .bind(encode_enum(&p.tsa_tier))
        .bind(&p.bundle_version)
        .bind(encode_enum(&p.transfer_policy))
        .bind(p.pricing_amount)
        .bind(&p.pricing_currency)
        .bind(encode_enum(&p.payment_provider))
        .bind(&p.min_client_version_warning)
        .bind(&p.min_client_version_required)
        .bind(bool_to_int(p.active))
        .bind(p.updated_at)
        .bind(uuid_to_blob(p.id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_term_declaration(&self, d: &ProductTermDeclaration) -> crate::Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO product_term_declarations \
             (product_id, warranty, refund, revocation, expiry, support_available, \
              support_channels, response_sla_hours, support_scope, support_coverage, updates_policy) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(d.product_id))
        .bind(&d.warranty)
        .bind(&d.refund)
        .bind(&d.revocation)
        .bind(&d.expiry)
        .bind(bool_to_int(d.support_available))
        .bind(&d.support_channels)
        .bind(d.response_sla_hours)
        .bind(&d.support_scope)
        .bind(&d.support_coverage)
        .bind(&d.updates_policy)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_term_declaration(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Option<ProductTermDeclaration>> {
        sqlx::query_as::<_, DbProductTermDeclaration>(
            "SELECT * FROM product_term_declarations WHERE product_id = ?",
        )
        .bind(uuid_to_blob(product_id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_term_declaration)
        .transpose()
    }

    async fn create_terms_document(&self, d: &ProductTermsDocument) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO product_terms_documents \
             (id, product_id, typst_source, rendered_hash, validation_status, \
              validation_findings, vendor_acknowledged_at, vendor_acknowledged_findings, \
              activated_at, created_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(d.id))
        .bind(uuid_to_blob(d.product_id))
        .bind(&d.typst_source)
        .bind(&d.rendered_hash)
        .bind(encode_enum(&d.validation_status))
        .bind(&d.validation_findings)
        .bind(d.vendor_acknowledged_at)
        .bind(&d.vendor_acknowledged_findings)
        .bind(d.activated_at)
        .bind(d.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_terms_document(&self, id: Uuid) -> crate::Result<Option<ProductTermsDocument>> {
        sqlx::query_as::<_, DbProductTermsDocument>(
            "SELECT * FROM product_terms_documents WHERE id = ?",
        )
        .bind(uuid_to_blob(id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_terms_document)
        .transpose()
    }

    async fn get_active_terms_document(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Option<ProductTermsDocument>> {
        sqlx::query_as::<_, DbProductTermsDocument>(
            "SELECT * FROM product_terms_documents WHERE product_id = ? AND activated_at IS NOT NULL",
        )
        .bind(uuid_to_blob(product_id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_terms_document)
        .transpose()
    }

    async fn list_terms_documents(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Vec<ProductTermsDocument>> {
        sqlx::query_as::<_, DbProductTermsDocument>(
            "SELECT * FROM product_terms_documents WHERE product_id = ? ORDER BY created_at ASC",
        )
        .bind(uuid_to_blob(product_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_terms_document)
        .collect()
    }

    async fn update_terms_document_validation(
        &self,
        id: Uuid,
        status: TermsValidationStatus,
        findings: &str,
    ) -> crate::Result<()> {
        sqlx::query(
            "UPDATE product_terms_documents SET validation_status = ?, validation_findings = ? WHERE id = ?",
        )
        .bind(encode_enum(&status))
        .bind(findings)
        .bind(uuid_to_blob(id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn acknowledge_terms_findings(
        &self,
        id: Uuid,
        acknowledged_at: i64,
        findings: &str,
    ) -> crate::Result<()> {
        sqlx::query(
            "UPDATE product_terms_documents SET vendor_acknowledged_at = ?, vendor_acknowledged_findings = ? WHERE id = ?",
        )
        .bind(acknowledged_at)
        .bind(findings)
        .bind(uuid_to_blob(id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn activate_terms_document(&self, id: Uuid, activated_at: i64) -> crate::Result<()> {
        let id_blob = uuid_to_blob(id);

        let row = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT product_id FROM product_terms_documents WHERE id = ?",
        )
        .bind(&id_blob)
        .fetch_optional(&self.pool)
        .await?;

        let product_id_blob = match row {
            Some(r) => r.0,
            None => return Err(crate::Error::NotFound),
        };

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "UPDATE product_terms_documents SET activated_at = NULL WHERE product_id = ? AND id != ?",
        )
        .bind(&product_id_blob)
        .bind(&id_blob)
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE product_terms_documents SET activated_at = ? WHERE id = ?")
            .bind(activated_at)
            .bind(&id_blob)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn replace_customer_fields(
        &self,
        product_id: Uuid,
        fields: &[ProductCustomerField],
    ) -> crate::Result<()> {
        let product_id_blob = uuid_to_blob(product_id);
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM product_customer_fields WHERE product_id = ?")
            .bind(&product_id_blob)
            .execute(&mut *tx)
            .await?;

        for f in fields {
            sqlx::query(
                "INSERT INTO product_customer_fields \
                 (id, product_id, field_key, required, gdpr_basis, purpose_description) \
                 VALUES (?,?,?,?,?,?)",
            )
            .bind(uuid_to_blob(f.id))
            .bind(&product_id_blob)
            .bind(&f.field_key)
            .bind(bool_to_int(f.required))
            .bind(encode_enum(&f.gdpr_basis))
            .bind(&f.purpose_description)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_customer_fields(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Vec<ProductCustomerField>> {
        sqlx::query_as::<_, DbProductCustomerField>(
            "SELECT * FROM product_customer_fields WHERE product_id = ?",
        )
        .bind(uuid_to_blob(product_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_customer_field)
        .collect()
    }

    async fn create_upgrade_policy(&self, p: &UpgradePolicyRow) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO upgrade_policies (id, product_id, from_version, to_version, policy, created_at) VALUES (?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(p.id))
        .bind(uuid_to_blob(p.product_id))
        .bind(&p.from_version)
        .bind(&p.to_version)
        .bind(encode_enum(&p.policy))
        .bind(p.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_upgrade_policy(&self, id: Uuid) -> crate::Result<Option<UpgradePolicyRow>> {
        sqlx::query_as::<_, DbUpgradePolicy>("SELECT * FROM upgrade_policies WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_upgrade_policy)
            .transpose()
    }

    async fn find_upgrade_policy(
        &self,
        product_id: Uuid,
        from_version: &str,
        to_version: &str,
    ) -> crate::Result<Option<UpgradePolicyRow>> {
        sqlx::query_as::<_, DbUpgradePolicy>(
            "SELECT * FROM upgrade_policies WHERE product_id = ? AND from_version = ? AND to_version = ?",
        )
        .bind(uuid_to_blob(product_id))
        .bind(from_version)
        .bind(to_version)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_upgrade_policy)
        .transpose()
    }

    async fn list_upgrade_policies(
        &self,
        product_id: Uuid,
    ) -> crate::Result<Vec<UpgradePolicyRow>> {
        sqlx::query_as::<_, DbUpgradePolicy>("SELECT * FROM upgrade_policies WHERE product_id = ?")
            .bind(uuid_to_blob(product_id))
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(from_db_upgrade_policy)
            .collect()
    }

    async fn delete_upgrade_policy(&self, id: Uuid) -> crate::Result<()> {
        let result = sqlx::query("DELETE FROM upgrade_policies WHERE id = ?")
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }
}

#[async_trait]
impl CustomerStore for SqliteStorage {
    async fn create_customer(&self, c: &Customer) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO customers (id, product_id, full_name, email, field_values, created_at, updated_at) \
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(c.id))
        .bind(uuid_to_blob(c.product_id))
        .bind(&c.full_name)
        .bind(&c.email)
        .bind(&c.field_values)
        .bind(c.created_at)
        .bind(c.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_customer(&self, id: Uuid) -> crate::Result<Option<Customer>> {
        sqlx::query_as::<_, DbCustomer>("SELECT * FROM customers WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_customer)
            .transpose()
    }

    async fn find_customer_by_email(
        &self,
        product_id: Uuid,
        email: &str,
    ) -> crate::Result<Option<Customer>> {
        sqlx::query_as::<_, DbCustomer>(
            "SELECT * FROM customers WHERE product_id = ? AND email = ?",
        )
        .bind(uuid_to_blob(product_id))
        .bind(email)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_customer)
        .transpose()
    }

    async fn update_customer(&self, c: &Customer) -> crate::Result<()> {
        sqlx::query(
            "UPDATE customers SET full_name = ?, email = ?, field_values = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&c.full_name)
        .bind(&c.email)
        .bind(&c.field_values)
        .bind(c.updated_at)
        .bind(uuid_to_blob(c.id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl LicenseStore for SqliteStorage {
    async fn create_consent_record(&self, r: &ConsentRecord) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO consent_records \
             (id, customer_id, license_id, terms_document_id, terms_rendered_hash, \
              checkboxes_ticked, accepted_at_ns, ip_address, client_version, protocol_version, \
              terms_findings_shown, payment_provider, payment_provider_tier) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(r.id))
        .bind(uuid_to_blob(r.customer_id))
        .bind(uuid_to_blob(r.license_id))
        .bind(uuid_to_blob(r.terms_document_id))
        .bind(&r.terms_rendered_hash)
        .bind(&r.checkboxes_ticked)
        .bind(r.accepted_at_ns)
        .bind(&r.ip_address)
        .bind(&r.client_version)
        .bind(r.protocol_version)
        .bind(&r.terms_findings_shown)
        .bind(encode_enum(&r.payment_provider))
        .bind(encode_enum(&r.payment_provider_tier))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_consent_record(&self, id: Uuid) -> crate::Result<Option<ConsentRecord>> {
        sqlx::query_as::<_, DbConsentRecord>("SELECT * FROM consent_records WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_consent_record)
            .transpose()
    }

    async fn get_consent_records_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<ConsentRecord>> {
        sqlx::query_as::<_, DbConsentRecord>("SELECT * FROM consent_records WHERE license_id = ?")
            .bind(uuid_to_blob(license_id))
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(from_db_consent_record)
            .collect()
    }

    async fn create_license(&self, l: &License) -> crate::Result<()> {
        let superseded_by = l.superseded_by.map(uuid_to_blob);
        sqlx::query(
            "INSERT INTO licenses \
             (id, customer_id, product_id, bundle_version, connectivity_mode, seat_count, \
              expiry_at, status, superseded_by, revoked_at, revocation_reason, created_at, email_sent_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(l.id))
        .bind(uuid_to_blob(l.customer_id))
        .bind(uuid_to_blob(l.product_id))
        .bind(&l.bundle_version)
        .bind(encode_enum(&l.connectivity_mode))
        .bind(l.seat_count)
        .bind(l.expiry_at)
        .bind(encode_enum(&l.status))
        .bind(superseded_by)
        .bind(l.revoked_at)
        .bind(&l.revocation_reason)
        .bind(l.created_at)
        .bind(l.email_sent_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_license(&self, id: Uuid) -> crate::Result<Option<License>> {
        sqlx::query_as::<_, DbLicense>("SELECT * FROM licenses WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_license)
            .transpose()
    }

    async fn list_licenses_for_customer(&self, customer_id: Uuid) -> crate::Result<Vec<License>> {
        sqlx::query_as::<_, DbLicense>(
            "SELECT * FROM licenses WHERE customer_id = ? ORDER BY created_at ASC",
        )
        .bind(uuid_to_blob(customer_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_license)
        .collect()
    }

    async fn update_license_status(
        &self,
        id: Uuid,
        status: LicenseStatus,
        revoked_at: Option<i64>,
        revocation_reason: Option<&str>,
        superseded_by: Option<Uuid>,
    ) -> crate::Result<()> {
        let superseded_by_blob = superseded_by.map(uuid_to_blob);
        sqlx::query(
            "UPDATE licenses SET status = ?, revoked_at = ?, revocation_reason = ?, superseded_by = ? WHERE id = ?",
        )
        .bind(encode_enum(&status))
        .bind(revoked_at)
        .bind(revocation_reason)
        .bind(superseded_by_blob)
        .bind(uuid_to_blob(id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_license_email_sent(&self, id: Uuid, sent_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE licenses SET email_sent_at = ? WHERE id = ?")
            .bind(sent_at)
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl SeatStore for SqliteStorage {
    async fn create_seat_binding(&self, b: &FingerprintSeatBinding) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO fingerprint_seat_bindings \
             (id, license_id, fingerprint_commitment, seat_index, bound_at, last_verified_at, revoked_at, transfer_pending_at) \
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(b.id))
        .bind(uuid_to_blob(b.license_id))
        .bind(&b.fingerprint_commitment)
        .bind(b.seat_index)
        .bind(b.bound_at)
        .bind(b.last_verified_at)
        .bind(b.revoked_at)
        .bind(b.transfer_pending_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_seat_binding(&self, id: Uuid) -> crate::Result<Option<FingerprintSeatBinding>> {
        sqlx::query_as::<_, DbFingerprintSeatBinding>(
            "SELECT * FROM fingerprint_seat_bindings WHERE id = ?",
        )
        .bind(uuid_to_blob(id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_seat_binding)
        .transpose()
    }

    async fn find_seat_binding_by_commitment(
        &self,
        license_id: Uuid,
        commitment: &[u8],
    ) -> crate::Result<Option<FingerprintSeatBinding>> {
        sqlx::query_as::<_, DbFingerprintSeatBinding>(
            "SELECT * FROM fingerprint_seat_bindings WHERE license_id = ? AND fingerprint_commitment = ?",
        )
        .bind(uuid_to_blob(license_id))
        .bind(commitment)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_seat_binding)
        .transpose()
    }

    async fn list_seat_bindings(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<FingerprintSeatBinding>> {
        sqlx::query_as::<_, DbFingerprintSeatBinding>(
            "SELECT * FROM fingerprint_seat_bindings WHERE license_id = ?",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_seat_binding)
        .collect()
    }

    async fn count_active_seat_bindings(&self, license_id: Uuid) -> crate::Result<u32> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM fingerprint_seat_bindings WHERE license_id = ? AND revoked_at IS NULL",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_one(&self.pool)
        .await?;
        Ok(u32::try_from(row.0)
            .map_err(|_| crate::Error::Corrupt("seat binding count out of u32 range".into()))?)
    }

    async fn revoke_seat_binding(&self, id: Uuid, revoked_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE fingerprint_seat_bindings SET revoked_at = ? WHERE id = ?")
            .bind(revoked_at)
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_seat_binding_verified(&self, id: Uuid, verified_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE fingerprint_seat_bindings SET last_verified_at = ? WHERE id = ?")
            .bind(verified_at)
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_issuance_secret(&self, s: &IssuanceSecret) -> crate::Result<()> {
        sqlx::query("INSERT INTO issuance_secrets (license_id, secret, created_at) VALUES (?,?,?)")
            .bind(uuid_to_blob(s.license_id))
            .bind(&s.secret)
            .bind(s.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_issuance_secret(&self, license_id: Uuid) -> crate::Result<Option<IssuanceSecret>> {
        sqlx::query_as::<_, DbIssuanceSecret>("SELECT * FROM issuance_secrets WHERE license_id = ?")
            .bind(uuid_to_blob(license_id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_issuance_secret)
            .transpose()
    }

    async fn delete_issuance_secret(&self, license_id: Uuid) -> crate::Result<()> {
        let result = sqlx::query("DELETE FROM issuance_secrets WHERE license_id = ?")
            .bind(uuid_to_blob(license_id))
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }

    async fn create_session(&self, s: &ActiveSession) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO active_sessions \
             (id, binding_id, ephemeral_pubkey, issued_at, expires_at, last_heartbeat_at, seq_no, status) \
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(s.id))
        .bind(uuid_to_blob(s.binding_id))
        .bind(&s.ephemeral_pubkey)
        .bind(s.issued_at)
        .bind(s.expires_at)
        .bind(s.last_heartbeat_at)
        .bind(s.seq_no)
        .bind(encode_enum(&s.status))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session(&self, id: Uuid) -> crate::Result<Option<ActiveSession>> {
        sqlx::query_as::<_, DbActiveSession>("SELECT * FROM active_sessions WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_active_session)
            .transpose()
    }

    async fn get_active_session_for_binding(
        &self,
        binding_id: Uuid,
    ) -> crate::Result<Option<ActiveSession>> {
        sqlx::query_as::<_, DbActiveSession>(
            "SELECT * FROM active_sessions WHERE binding_id = ? AND status = 'Active'",
        )
        .bind(uuid_to_blob(binding_id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_active_session)
        .transpose()
    }

    async fn update_session_heartbeat(
        &self,
        id: Uuid,
        heartbeat_at: i64,
        seq_no: i64,
    ) -> crate::Result<()> {
        sqlx::query("UPDATE active_sessions SET last_heartbeat_at = ?, seq_no = ? WHERE id = ?")
            .bind(heartbeat_at)
            .bind(seq_no)
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_session_status(&self, id: Uuid, status: SessionStatus) -> crate::Result<()> {
        sqlx::query("UPDATE active_sessions SET status = ? WHERE id = ?")
            .bind(encode_enum(&status))
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn expire_sessions_before(&self, expires_at: i64) -> crate::Result<u64> {
        let result = sqlx::query(
            "UPDATE active_sessions SET status = 'Expired' WHERE expires_at < ? AND status = 'Active'",
        )
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl PaymentStore for SqliteStorage {
    async fn create_payment_transaction(&self, t: &PaymentTransaction) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO payment_transactions \
             (id, license_id, provider, provider_transaction_id, amount, currency, \
              provider_tier, test_mode, status, created_at, confirmed_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(t.id))
        .bind(uuid_to_blob(t.license_id))
        .bind(encode_enum(&t.provider))
        .bind(&t.provider_transaction_id)
        .bind(t.amount)
        .bind(&t.currency)
        .bind(encode_enum(&t.provider_tier))
        .bind(bool_to_int(t.test_mode))
        .bind(encode_enum(&t.status))
        .bind(t.created_at)
        .bind(t.confirmed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_payment_transaction(&self, id: Uuid) -> crate::Result<Option<PaymentTransaction>> {
        sqlx::query_as::<_, DbPaymentTransaction>("SELECT * FROM payment_transactions WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_payment_transaction)
            .transpose()
    }

    async fn get_payment_transaction_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Option<PaymentTransaction>> {
        sqlx::query_as::<_, DbPaymentTransaction>(
            "SELECT * FROM payment_transactions WHERE license_id = ?",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_payment_transaction)
        .transpose()
    }

    async fn update_payment_status(
        &self,
        id: Uuid,
        status: PaymentStatus,
        confirmed_at: Option<i64>,
    ) -> crate::Result<()> {
        sqlx::query("UPDATE payment_transactions SET status = ?, confirmed_at = ? WHERE id = ?")
            .bind(encode_enum(&status))
            .bind(confirmed_at)
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_transfer_request(&self, r: &TransferRequest) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO transfer_requests \
             (id, license_id, old_fingerprint_commitment, new_fingerprint_commitment, \
              requested_at, status, vendor_note, resolved_at) \
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(r.id))
        .bind(uuid_to_blob(r.license_id))
        .bind(&r.old_fingerprint_commitment)
        .bind(&r.new_fingerprint_commitment)
        .bind(r.requested_at)
        .bind(encode_enum(&r.status))
        .bind(&r.vendor_note)
        .bind(r.resolved_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_transfer_request(&self, id: Uuid) -> crate::Result<Option<TransferRequest>> {
        sqlx::query_as::<_, DbTransferRequest>("SELECT * FROM transfer_requests WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_transfer_request)
            .transpose()
    }

    async fn list_transfer_requests_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<TransferRequest>> {
        sqlx::query_as::<_, DbTransferRequest>(
            "SELECT * FROM transfer_requests WHERE license_id = ? ORDER BY requested_at ASC",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_transfer_request)
        .collect()
    }

    async fn resolve_transfer_request(
        &self,
        id: Uuid,
        status: TransferStatus,
        vendor_note: Option<&str>,
        resolved_at: i64,
    ) -> crate::Result<()> {
        sqlx::query(
            "UPDATE transfer_requests SET status = ?, vendor_note = ?, resolved_at = ? WHERE id = ?",
        )
        .bind(encode_enum(&status))
        .bind(vendor_note)
        .bind(resolved_at)
        .bind(uuid_to_blob(id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl SecurityStore for SqliteStorage {
    async fn create_quarantine_case(&self, c: &QuarantineCase) -> crate::Result<()> {
        let session_id_blob = c.session_id.map(uuid_to_blob);
        sqlx::query(
            "INSERT INTO quarantine_cases \
             (id, case_id, binding_id, session_id, trigger, triggered_at, status, \
              resolution, resolved_at, vendor_note) \
             VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(c.id))
        .bind(uuid_to_blob(c.case_id))
        .bind(uuid_to_blob(c.binding_id))
        .bind(session_id_blob)
        .bind(encode_enum(&c.trigger))
        .bind(c.triggered_at)
        .bind(encode_enum(&c.status))
        .bind(&c.resolution)
        .bind(c.resolved_at)
        .bind(&c.vendor_note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_quarantine_case(&self, id: Uuid) -> crate::Result<Option<QuarantineCase>> {
        sqlx::query_as::<_, DbQuarantineCase>("SELECT * FROM quarantine_cases WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_quarantine_case)
            .transpose()
    }

    async fn get_quarantine_case_by_case_id(
        &self,
        case_id: Uuid,
    ) -> crate::Result<Option<QuarantineCase>> {
        sqlx::query_as::<_, DbQuarantineCase>("SELECT * FROM quarantine_cases WHERE case_id = ?")
            .bind(uuid_to_blob(case_id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_quarantine_case)
            .transpose()
    }

    async fn resolve_quarantine_case(
        &self,
        id: Uuid,
        status: QuarantineStatus,
        resolution: Option<&str>,
        resolved_at: i64,
        vendor_note: Option<&str>,
    ) -> crate::Result<()> {
        sqlx::query(
            "UPDATE quarantine_cases SET status = ?, resolution = ?, resolved_at = ?, vendor_note = ? WHERE id = ?",
        )
        .bind(encode_enum(&status))
        .bind(resolution)
        .bind(resolved_at)
        .bind(vendor_note)
        .bind(uuid_to_blob(id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_security_event(&self, e: &SecurityEvent) -> crate::Result<()> {
        let session_id_blob = e.session_id.map(uuid_to_blob);
        let case_id_blob = e.case_id.map(uuid_to_blob);
        sqlx::query(
            "INSERT INTO security_events \
             (event_id, license_id, binding_id, session_id, occurred_at_ns, received_at_ns, \
              event_type, severity, payload, response, reviewed_by, reviewed_at, case_id) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(e.event_id))
        .bind(uuid_to_blob(e.license_id))
        .bind(uuid_to_blob(e.binding_id))
        .bind(session_id_blob)
        .bind(e.occurred_at_ns)
        .bind(e.received_at_ns)
        .bind(&e.event_type)
        .bind(encode_enum(&e.severity))
        .bind(&e.payload)
        .bind(encode_enum(&e.response))
        .bind(&e.reviewed_by)
        .bind(e.reviewed_at)
        .bind(case_id_blob)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_security_events_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<SecurityEvent>> {
        sqlx::query_as::<_, DbSecurityEvent>(
            "SELECT * FROM security_events WHERE license_id = ? ORDER BY occurred_at_ns ASC",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_security_event)
        .collect()
    }

    async fn mark_security_event_reviewed(
        &self,
        id: i64,
        reviewed_by: &str,
        reviewed_at: i64,
    ) -> crate::Result<()> {
        sqlx::query("UPDATE security_events SET reviewed_by = ?, reviewed_at = ? WHERE id = ?")
            .bind(reviewed_by)
            .bind(reviewed_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_revocation_record(&self, r: &RevocationRecord) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO revocation_records (license_id, revoked_at, revoked_by, reason) VALUES (?,?,?,?)",
        )
        .bind(uuid_to_blob(r.license_id))
        .bind(r.revoked_at)
        .bind(encode_enum(&r.revoked_by))
        .bind(&r.reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_revocation_record(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Option<RevocationRecord>> {
        sqlx::query_as::<_, DbRevocationRecord>(
            "SELECT * FROM revocation_records WHERE license_id = ?",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_revocation_record)
        .transpose()
    }

    async fn create_email_log_entry(&self, e: &EmailLogEntry) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO email_log (id, license_id, email_type, sent_to, sent_at, success, error_message) \
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(e.id))
        .bind(uuid_to_blob(e.license_id))
        .bind(encode_enum(&e.email_type))
        .bind(&e.sent_to)
        .bind(e.sent_at)
        .bind(bool_to_int(e.success))
        .bind(&e.error_message)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_email_log_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<EmailLogEntry>> {
        sqlx::query_as::<_, DbEmailLogEntry>(
            "SELECT * FROM email_log WHERE license_id = ? ORDER BY sent_at ASC",
        )
        .bind(uuid_to_blob(license_id))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_email_log_entry)
        .collect()
    }
}

#[async_trait]
impl EnrollmentStore for SqliteStorage {
    async fn count_transferable_seat_bindings(&self, product_id: Uuid) -> crate::Result<u32> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM fingerprint_seat_bindings fsb \
             JOIN licenses l ON l.id = fsb.license_id \
             WHERE l.product_id = ? AND fsb.revoked_at IS NULL AND fsb.transfer_pending_at IS NULL",
        )
        .bind(uuid_to_blob(product_id))
        .fetch_one(&self.pool)
        .await?;
        Ok(u32::try_from(row.0).map_err(|_| {
            crate::Error::Corrupt("transferable binding count out of u32 range".into())
        })?)
    }

    async fn set_seat_binding_transfer_pending(
        &self,
        id: Uuid,
        pending_at: Option<i64>,
    ) -> crate::Result<()> {
        sqlx::query("UPDATE fingerprint_seat_bindings SET transfer_pending_at = ? WHERE id = ?")
            .bind(pending_at)
            .bind(uuid_to_blob(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_enrollment_session(&self, s: &EnrollmentSession) -> crate::Result<()> {
        let terms_doc_id = s.terms_document_id.map(uuid_to_blob);
        let transfer_req_id = s.transfer_request_id.map(uuid_to_blob);
        let license_id_blob = s.license_id.map(uuid_to_blob);
        sqlx::query(
            "INSERT INTO enrollment_sessions \
             (id, product_id, fingerprint_commitment, customer_pubkey, client_version, \
              protocol_version, state, offer_nonce, offer_expires_at, terms_document_id, \
              request_bytes, offer_bytes, receipt_bytes, payment_intent_id, payment_captured, \
              grant_bytes, transfer_request_id, license_id, abandon_reason, created_at, updated_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(uuid_to_blob(s.id))
        .bind(uuid_to_blob(s.product_id))
        .bind(&s.fingerprint_commitment)
        .bind(&s.customer_pubkey)
        .bind(&s.client_version)
        .bind(s.protocol_version)
        .bind(encode_enum(&s.state))
        .bind(&s.offer_nonce)
        .bind(s.offer_expires_at)
        .bind(terms_doc_id)
        .bind(&s.request_bytes)
        .bind(&s.offer_bytes)
        .bind(&s.receipt_bytes)
        .bind(&s.payment_intent_id)
        .bind(bool_to_int(s.payment_captured))
        .bind(&s.grant_bytes)
        .bind(transfer_req_id)
        .bind(license_id_blob)
        .bind(&s.abandon_reason)
        .bind(s.created_at)
        .bind(s.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_enrollment_session(&self, id: Uuid) -> crate::Result<Option<EnrollmentSession>> {
        sqlx::query_as::<_, DbEnrollmentSession>("SELECT * FROM enrollment_sessions WHERE id = ?")
            .bind(uuid_to_blob(id))
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_enrollment_session)
            .transpose()
    }

    async fn get_session_by_payment_intent(
        &self,
        intent_id: &str,
    ) -> crate::Result<Option<EnrollmentSession>> {
        sqlx::query_as::<_, DbEnrollmentSession>(
            "SELECT * FROM enrollment_sessions WHERE payment_intent_id = ?",
        )
        .bind(intent_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_enrollment_session)
        .transpose()
    }

    async fn update_enrollment_session(
        &self,
        id: Uuid,
        expected_updated_at: i64,
        update: EnrollmentSessionUpdate,
    ) -> crate::Result<()> {
        let mut sets: Vec<&str> = Vec::new();
        if update.state.is_some() {
            sets.push("state = ?");
        }
        if update.receipt_bytes.is_some() {
            sets.push("receipt_bytes = ?");
        }
        if update.payment_intent_id.is_some() {
            sets.push("payment_intent_id = ?");
        }
        if update.payment_captured.is_some() {
            sets.push("payment_captured = ?");
        }
        if update.grant_bytes.is_some() {
            sets.push("grant_bytes = ?");
        }
        if update.license_id.is_some() {
            sets.push("license_id = ?");
        }
        if update.abandon_reason.is_some() {
            sets.push("abandon_reason = ?");
        }
        sets.push("updated_at = ?");

        let sql = format!(
            "UPDATE enrollment_sessions SET {} WHERE id = ? AND (updated_at = ? OR ? = 0)",
            sets.join(", ")
        );

        let mut q = sqlx::query(&sql);
        if let Some(v) = update.state {
            q = q.bind(encode_enum(&v));
        }
        if let Some(v) = update.receipt_bytes {
            q = q.bind(v);
        }
        if let Some(v) = update.payment_intent_id {
            q = q.bind(v);
        }
        if let Some(v) = update.payment_captured {
            q = q.bind(bool_to_int(v));
        }
        if let Some(v) = update.grant_bytes {
            q = q.bind(v);
        }
        if let Some(v) = update.license_id {
            q = q.bind(v.map(uuid_to_blob));
        }
        if let Some(v) = update.abandon_reason {
            q = q.bind(v);
        }
        q = q.bind(update.updated_at);
        q = q.bind(uuid_to_blob(id));
        q = q.bind(expected_updated_at);
        q = q.bind(expected_updated_at);

        let result = q.execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(crate::Error::Conflict("concurrent update".to_string()));
        }
        Ok(())
    }

    async fn list_grant_ready_sessions(&self) -> crate::Result<Vec<EnrollmentSession>> {
        sqlx::query_as::<_, DbEnrollmentSession>(
            "SELECT * FROM enrollment_sessions WHERE state = 'GrantReady'",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_enrollment_session)
        .collect()
    }
}
