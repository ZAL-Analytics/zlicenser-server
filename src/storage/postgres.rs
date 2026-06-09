use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[allow(clippy::wildcard_imports)] // storage impls use all domain types from this module
use crate::storage::types::*;
use crate::storage::{
    CustomerStore, EnrollmentStore, LicenseStore, PaymentStore, SeatStore, SecurityStore,
    VendorStore,
};

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> crate::Result<Self> {
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(|e| crate::Error::Database(e.to_string()))?;

        sqlx::migrate!("migrations/postgres")
            .run(&pool)
            .await
            .map_err(|e| crate::Error::Migration(e.to_string()))?;

        Ok(Self { pool })
    }
}

fn encode_enum<T: std::fmt::Display>(t: &T) -> String {
    t.to_string()
}

fn decode_enum<T: std::str::FromStr<Err = crate::Error>>(s: impl AsRef<str>) -> crate::Result<T> {
    s.as_ref().parse()
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
    id: Uuid,
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
    auto_quarantine_on_critical: bool,
    active: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbProductTermDeclaration {
    product_id: Uuid,
    warranty: String,
    refund: String,
    revocation: String,
    expiry: String,
    support_available: bool,
    support_channels: String,
    response_sla_hours: Option<i64>,
    support_scope: Option<String>,
    support_coverage: Option<String>,
    updates_policy: String,
}

#[derive(sqlx::FromRow)]
struct DbProductTermsDocument {
    id: Uuid,
    product_id: Uuid,
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
    id: Uuid,
    product_id: Uuid,
    field_key: String,
    required: bool,
    gdpr_basis: String,
    purpose_description: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbUpgradePolicy {
    id: Uuid,
    product_id: Uuid,
    from_version: String,
    to_version: String,
    policy: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbCustomer {
    id: Uuid,
    product_id: Uuid,
    full_name: String,
    email: String,
    field_values: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbConsentRecord {
    id: Uuid,
    customer_id: Uuid,
    license_id: Uuid,
    terms_document_id: Uuid,
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
    id: Uuid,
    customer_id: Uuid,
    product_id: Uuid,
    bundle_version: String,
    connectivity_mode: String,
    seat_count: i64,
    expiry_at: Option<i64>,
    status: String,
    superseded_by: Option<Uuid>,
    revoked_at: Option<i64>,
    revocation_reason: Option<String>,
    created_at: i64,
    email_sent_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbFingerprintSeatBinding {
    id: Uuid,
    license_id: Uuid,
    fingerprint_commitment: Vec<u8>,
    seat_index: i64,
    bound_at: i64,
    last_verified_at: Option<i64>,
    revoked_at: Option<i64>,
    transfer_pending_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbIssuanceSecret {
    license_id: Uuid,
    secret: Vec<u8>,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbPaymentTransaction {
    id: Uuid,
    license_id: Uuid,
    provider: String,
    provider_transaction_id: String,
    amount: i64,
    currency: String,
    provider_tier: String,
    test_mode: bool,
    status: String,
    created_at: i64,
    confirmed_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbTransferRequest {
    id: Uuid,
    license_id: Uuid,
    old_fingerprint_commitment: Vec<u8>,
    new_fingerprint_commitment: Vec<u8>,
    requested_at: i64,
    status: String,
    vendor_note: Option<String>,
    resolved_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbActiveSession {
    id: Uuid,
    binding_id: Uuid,
    license_id: Uuid,
    product_id: Uuid,
    session_token: Vec<u8>,
    session_hmac_key_encrypted: Vec<u8>,
    heartbeat_interval_secs: i32,
    heartbeat_grace_secs: i32,
    shutdown_countdown_secs: i32,
    seq_no: i64,
    last_heartbeat_at: Option<i64>,
    expires_at: i64,
    status: String,
    command_pending: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct DbQuarantineCase {
    id: Uuid,
    case_id: Uuid,
    binding_id: Uuid,
    session_id: Option<Uuid>,
    trigger: String,
    trigger_event_id: Option<Uuid>,
    reason: String,
    created_at: i64,
    resumed_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbSecurityEventRecord {
    id: i64,
    event_id: Uuid,
    license_id: Uuid,
    binding_id: Uuid,
    session_id: Option<Uuid>,
    occurred_at_ns: i64,
    received_at_ns: i64,
    event_type: String,
    payload: String,
    severity: String,
    response_type: String,
    case_id: Option<Uuid>,
    reviewed_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DbRevocationRecord {
    license_id: Uuid,
    revoked_at: i64,
    revoked_by: String,
    reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DbEmailLogEntry {
    id: Uuid,
    license_id: Uuid,
    email_type: String,
    sent_to: String,
    sent_at: i64,
    success: bool,
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
        id: r.id,
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
        auto_quarantine_on_critical: r.auto_quarantine_on_critical,
        active: r.active,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

#[allow(clippy::unnecessary_wraps)] // consistent with other from_db_* functions that do need Result
fn from_db_term_declaration(r: DbProductTermDeclaration) -> crate::Result<ProductTermDeclaration> {
    Ok(ProductTermDeclaration {
        product_id: r.product_id,
        warranty: r.warranty,
        refund: r.refund,
        revocation: r.revocation,
        expiry: r.expiry,
        support_available: r.support_available,
        support_channels: r.support_channels,
        response_sla_hours: r.response_sla_hours,
        support_scope: r.support_scope,
        support_coverage: r.support_coverage,
        updates_policy: r.updates_policy,
    })
}

fn from_db_terms_document(r: DbProductTermsDocument) -> crate::Result<ProductTermsDocument> {
    Ok(ProductTermsDocument {
        id: r.id,
        product_id: r.product_id,
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
        id: r.id,
        product_id: r.product_id,
        field_key: r.field_key,
        required: r.required,
        gdpr_basis: decode_enum(r.gdpr_basis)?,
        purpose_description: r.purpose_description,
    })
}

fn from_db_upgrade_policy(r: DbUpgradePolicy) -> crate::Result<UpgradePolicyRow> {
    Ok(UpgradePolicyRow {
        id: r.id,
        product_id: r.product_id,
        from_version: r.from_version,
        to_version: r.to_version,
        policy: decode_enum(r.policy)?,
        created_at: r.created_at,
    })
}

#[allow(clippy::unnecessary_wraps)] // consistent with other from_db_* functions that do need Result
fn from_db_customer(r: DbCustomer) -> crate::Result<Customer> {
    Ok(Customer {
        id: r.id,
        product_id: r.product_id,
        full_name: r.full_name,
        email: r.email,
        field_values: r.field_values,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

fn from_db_consent_record(r: DbConsentRecord) -> crate::Result<ConsentRecord> {
    Ok(ConsentRecord {
        id: r.id,
        customer_id: r.customer_id,
        license_id: r.license_id,
        terms_document_id: r.terms_document_id,
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
        id: r.id,
        customer_id: r.customer_id,
        product_id: r.product_id,
        bundle_version: r.bundle_version,
        connectivity_mode: decode_enum(r.connectivity_mode)?,
        seat_count: r.seat_count,
        expiry_at: r.expiry_at,
        status: decode_enum(r.status)?,
        superseded_by: r.superseded_by,
        revoked_at: r.revoked_at,
        revocation_reason: r.revocation_reason,
        created_at: r.created_at,
        email_sent_at: r.email_sent_at,
    })
}

#[allow(clippy::unnecessary_wraps)] // consistent with other from_db_* functions that do need Result
fn from_db_seat_binding(r: DbFingerprintSeatBinding) -> crate::Result<FingerprintSeatBinding> {
    Ok(FingerprintSeatBinding {
        id: r.id,
        license_id: r.license_id,
        fingerprint_commitment: r.fingerprint_commitment,
        seat_index: r.seat_index,
        bound_at: r.bound_at,
        last_verified_at: r.last_verified_at,
        revoked_at: r.revoked_at,
        transfer_pending_at: r.transfer_pending_at,
    })
}

#[allow(clippy::unnecessary_wraps)] // consistent with other from_db_* functions that do need Result
fn from_db_issuance_secret(r: DbIssuanceSecret) -> crate::Result<IssuanceSecret> {
    Ok(IssuanceSecret {
        license_id: r.license_id,
        secret: r.secret,
        created_at: r.created_at,
    })
}

fn from_db_payment_transaction(r: DbPaymentTransaction) -> crate::Result<PaymentTransaction> {
    Ok(PaymentTransaction {
        id: r.id,
        license_id: r.license_id,
        provider: decode_enum(r.provider)?,
        provider_transaction_id: r.provider_transaction_id,
        amount: r.amount,
        currency: r.currency,
        provider_tier: decode_enum(r.provider_tier)?,
        test_mode: r.test_mode,
        status: decode_enum(r.status)?,
        created_at: r.created_at,
        confirmed_at: r.confirmed_at,
    })
}

fn from_db_transfer_request(r: DbTransferRequest) -> crate::Result<TransferRequest> {
    Ok(TransferRequest {
        id: r.id,
        license_id: r.license_id,
        old_fingerprint_commitment: r.old_fingerprint_commitment,
        new_fingerprint_commitment: r.new_fingerprint_commitment,
        requested_at: r.requested_at,
        status: decode_enum(r.status)?,
        vendor_note: r.vendor_note,
        resolved_at: r.resolved_at,
    })
}

fn from_db_active_session(r: DbActiveSession) -> crate::Result<ActiveSession> {
    let session_token = <[u8; 32]>::try_from(r.session_token.as_slice())
        .map_err(|_| crate::Error::Corrupt("session_token must be 32 bytes".into()))?;
    let session_hmac_key_encrypted = <[u8; 60]>::try_from(r.session_hmac_key_encrypted.as_slice())
        .map_err(|_| crate::Error::Corrupt("session_hmac_key_encrypted must be 60 bytes".into()))?;
    Ok(ActiveSession {
        id: r.id,
        binding_id: r.binding_id,
        license_id: r.license_id,
        product_id: r.product_id,
        session_token,
        session_hmac_key_encrypted,
        heartbeat_interval_secs: u32::try_from(r.heartbeat_interval_secs)
            .map_err(|_| crate::Error::Corrupt("heartbeat_interval_secs out of range".into()))?,
        heartbeat_grace_secs: u32::try_from(r.heartbeat_grace_secs)
            .map_err(|_| crate::Error::Corrupt("heartbeat_grace_secs out of range".into()))?,
        shutdown_countdown_secs: u32::try_from(r.shutdown_countdown_secs)
            .map_err(|_| crate::Error::Corrupt("shutdown_countdown_secs out of range".into()))?,
        seq_no: u64::try_from(r.seq_no)
            .map_err(|_| crate::Error::Corrupt("seq_no out of range".into()))?,
        last_heartbeat_at: r.last_heartbeat_at,
        expires_at: r.expires_at,
        status: decode_enum(r.status)?,
        command_pending: r.command_pending.map(decode_enum).transpose()?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

fn from_db_quarantine_case(r: DbQuarantineCase) -> crate::Result<QuarantineCase> {
    Ok(QuarantineCase {
        id: r.id,
        case_id: r.case_id,
        binding_id: r.binding_id,
        session_id: r.session_id,
        trigger: decode_enum(r.trigger)?,
        trigger_event_id: r.trigger_event_id,
        reason: r.reason,
        created_at: r.created_at,
        resumed_at: r.resumed_at,
    })
}

#[allow(clippy::unnecessary_wraps)] // consistent with other from_db_* functions that do need Result
fn from_db_security_event_record(r: DbSecurityEventRecord) -> crate::Result<SecurityEventRecord> {
    Ok(SecurityEventRecord {
        id: r.id,
        event_id: r.event_id,
        license_id: r.license_id,
        binding_id: r.binding_id,
        session_id: r.session_id,
        occurred_at_ns: r.occurred_at_ns,
        received_at_ns: r.received_at_ns,
        event_type: r.event_type,
        payload: r.payload,
        severity: r.severity,
        response_type: r.response_type,
        case_id: r.case_id,
        reviewed_at: r.reviewed_at,
    })
}

fn from_db_revocation_record(r: DbRevocationRecord) -> crate::Result<RevocationRecord> {
    Ok(RevocationRecord {
        license_id: r.license_id,
        revoked_at: r.revoked_at,
        revoked_by: decode_enum(r.revoked_by)?,
        reason: r.reason,
    })
}

fn from_db_email_log_entry(r: DbEmailLogEntry) -> crate::Result<EmailLogEntry> {
    Ok(EmailLogEntry {
        id: r.id,
        license_id: r.license_id,
        email_type: decode_enum(r.email_type)?,
        sent_to: r.sent_to,
        sent_at: r.sent_at,
        success: r.success,
        error_message: r.error_message,
    })
}

#[derive(sqlx::FromRow)]
struct DbEnrollmentSession {
    id: Uuid,
    product_id: Uuid,
    fingerprint_commitment: Vec<u8>,
    customer_pubkey: Vec<u8>,
    client_version: String,
    protocol_version: i64,
    state: String,
    offer_nonce: Option<Vec<u8>>,
    offer_expires_at: Option<i64>,
    terms_document_id: Option<Uuid>,
    request_bytes: Vec<u8>,
    offer_bytes: Option<Vec<u8>>,
    receipt_bytes: Option<Vec<u8>>,
    payment_intent_id: Option<String>,
    payment_captured: bool,
    grant_bytes: Option<Vec<u8>>,
    transfer_request_id: Option<Uuid>,
    license_id: Option<Uuid>,
    abandon_reason: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn from_db_enrollment_session(r: DbEnrollmentSession) -> crate::Result<EnrollmentSession> {
    Ok(EnrollmentSession {
        id: r.id,
        product_id: r.product_id,
        fingerprint_commitment: r.fingerprint_commitment,
        customer_pubkey: r.customer_pubkey,
        client_version: r.client_version,
        protocol_version: r.protocol_version,
        state: decode_enum(r.state)?,
        offer_nonce: r.offer_nonce,
        offer_expires_at: r.offer_expires_at,
        terms_document_id: r.terms_document_id,
        request_bytes: r.request_bytes,
        offer_bytes: r.offer_bytes,
        receipt_bytes: r.receipt_bytes,
        payment_intent_id: r.payment_intent_id,
        payment_captured: r.payment_captured,
        grant_bytes: r.grant_bytes,
        transfer_request_id: r.transfer_request_id,
        license_id: r.license_id,
        abandon_reason: r.abandon_reason,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

#[async_trait]
impl VendorStore for PostgresStorage {
    async fn get_vendor_config(&self) -> crate::Result<Option<VendorConfig>> {
        sqlx::query_as::<_, DbVendorConfig>("SELECT * FROM vendor_config WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_vendor_config)
            .transpose()
    }

    async fn upsert_vendor_config(&self, config: &VendorConfig) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO vendor_config \
             (id, public_key, public_key_fingerprint, registered_at, rotated_from_key, rotated_at) \
             VALUES (1, $1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET \
             public_key = EXCLUDED.public_key, \
             public_key_fingerprint = EXCLUDED.public_key_fingerprint, \
             registered_at = EXCLUDED.registered_at, \
             rotated_from_key = EXCLUDED.rotated_from_key, \
             rotated_at = EXCLUDED.rotated_at",
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
            "UPDATE vendor_config SET public_key = $1, public_key_fingerprint = $2, \
             rotated_from_key = $3, rotated_at = $4 WHERE id = 1",
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
              auto_quarantine_on_critical, active, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)",
        )
        .bind(p.id)
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
        .bind(p.auto_quarantine_on_critical)
        .bind(p.active)
        .bind(p.created_at)
        .bind(p.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_product(&self, id: Uuid) -> crate::Result<Option<Product>> {
        sqlx::query_as::<_, DbProduct>("SELECT * FROM products WHERE id = $1")
            .bind(id)
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
             name = $1, description = $2, connectivity_mode = $3, seat_count = $4, \
             expiry_policy = $5, grace_period_days = $6, heartbeat_interval_secs = $7, \
             heartbeat_grace_secs = $8, shutdown_countdown_secs = $9, tsa_tier = $10, \
             bundle_version = $11, transfer_policy = $12, pricing_amount = $13, \
             pricing_currency = $14, payment_provider = $15, min_client_version_warning = $16, \
             min_client_version_required = $17, auto_quarantine_on_critical = $18, \
             active = $19, updated_at = $20 \
             WHERE id = $21",
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
        .bind(p.auto_quarantine_on_critical)
        .bind(p.active)
        .bind(p.updated_at)
        .bind(p.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_term_declaration(&self, d: &ProductTermDeclaration) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO product_term_declarations \
             (product_id, warranty, refund, revocation, expiry, support_available, \
              support_channels, response_sla_hours, support_scope, support_coverage, updates_policy) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
             ON CONFLICT (product_id) DO UPDATE SET \
             warranty = EXCLUDED.warranty, refund = EXCLUDED.refund, \
             revocation = EXCLUDED.revocation, expiry = EXCLUDED.expiry, \
             support_available = EXCLUDED.support_available, support_channels = EXCLUDED.support_channels, \
             response_sla_hours = EXCLUDED.response_sla_hours, support_scope = EXCLUDED.support_scope, \
             support_coverage = EXCLUDED.support_coverage, updates_policy = EXCLUDED.updates_policy",
        )
        .bind(d.product_id)
        .bind(&d.warranty)
        .bind(&d.refund)
        .bind(&d.revocation)
        .bind(&d.expiry)
        .bind(d.support_available)
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
            "SELECT * FROM product_term_declarations WHERE product_id = $1",
        )
        .bind(product_id)
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
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(d.id)
        .bind(d.product_id)
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
            "SELECT * FROM product_terms_documents WHERE id = $1",
        )
        .bind(id)
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
            "SELECT * FROM product_terms_documents WHERE product_id = $1 AND activated_at IS NOT NULL",
        )
        .bind(product_id)
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
            "SELECT * FROM product_terms_documents WHERE product_id = $1 ORDER BY created_at ASC",
        )
        .bind(product_id)
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
            "UPDATE product_terms_documents SET validation_status = $1, validation_findings = $2 WHERE id = $3",
        )
        .bind(encode_enum(&status))
        .bind(findings)
        .bind(id)
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
            "UPDATE product_terms_documents SET vendor_acknowledged_at = $1, vendor_acknowledged_findings = $2 WHERE id = $3",
        )
        .bind(acknowledged_at)
        .bind(findings)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn activate_terms_document(&self, id: Uuid, activated_at: i64) -> crate::Result<()> {
        let row = sqlx::query_as::<_, (Uuid,)>(
            "SELECT product_id FROM product_terms_documents WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        let product_id = match row {
            Some(r) => r.0,
            None => return Err(crate::Error::NotFound),
        };

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "UPDATE product_terms_documents SET activated_at = NULL WHERE product_id = $1 AND id != $2",
        )
        .bind(product_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE product_terms_documents SET activated_at = $1 WHERE id = $2")
            .bind(activated_at)
            .bind(id)
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
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM product_customer_fields WHERE product_id = $1")
            .bind(product_id)
            .execute(&mut *tx)
            .await?;

        for f in fields {
            sqlx::query(
                "INSERT INTO product_customer_fields \
                 (id, product_id, field_key, required, gdpr_basis, purpose_description) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(f.id)
            .bind(product_id)
            .bind(&f.field_key)
            .bind(f.required)
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
            "SELECT * FROM product_customer_fields WHERE product_id = $1",
        )
        .bind(product_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_customer_field)
        .collect()
    }

    async fn create_upgrade_policy(&self, p: &UpgradePolicyRow) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO upgrade_policies (id, product_id, from_version, to_version, policy, created_at) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(p.id)
        .bind(p.product_id)
        .bind(&p.from_version)
        .bind(&p.to_version)
        .bind(encode_enum(&p.policy))
        .bind(p.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_upgrade_policy(&self, id: Uuid) -> crate::Result<Option<UpgradePolicyRow>> {
        sqlx::query_as::<_, DbUpgradePolicy>("SELECT * FROM upgrade_policies WHERE id = $1")
            .bind(id)
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
            "SELECT * FROM upgrade_policies WHERE product_id = $1 AND from_version = $2 AND to_version = $3",
        )
        .bind(product_id)
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
        sqlx::query_as::<_, DbUpgradePolicy>("SELECT * FROM upgrade_policies WHERE product_id = $1")
            .bind(product_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(from_db_upgrade_policy)
            .collect()
    }

    async fn delete_upgrade_policy(&self, id: Uuid) -> crate::Result<()> {
        let result = sqlx::query("DELETE FROM upgrade_policies WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }
}

#[async_trait]
impl CustomerStore for PostgresStorage {
    async fn create_customer(&self, c: &Customer) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO customers (id, product_id, full_name, email, field_values, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(c.id)
        .bind(c.product_id)
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
        sqlx::query_as::<_, DbCustomer>("SELECT * FROM customers WHERE id = $1")
            .bind(id)
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
            "SELECT * FROM customers WHERE product_id = $1 AND email = $2",
        )
        .bind(product_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_customer)
        .transpose()
    }

    async fn update_customer(&self, c: &Customer) -> crate::Result<()> {
        sqlx::query(
            "UPDATE customers SET full_name = $1, email = $2, field_values = $3, updated_at = $4 WHERE id = $5",
        )
        .bind(&c.full_name)
        .bind(&c.email)
        .bind(&c.field_values)
        .bind(c.updated_at)
        .bind(c.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl LicenseStore for PostgresStorage {
    async fn create_consent_record(&self, r: &ConsentRecord) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO consent_records \
             (id, customer_id, license_id, terms_document_id, terms_rendered_hash, \
              checkboxes_ticked, accepted_at_ns, ip_address, client_version, protocol_version, \
              terms_findings_shown, payment_provider, payment_provider_tier) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(r.id)
        .bind(r.customer_id)
        .bind(r.license_id)
        .bind(r.terms_document_id)
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
        sqlx::query_as::<_, DbConsentRecord>("SELECT * FROM consent_records WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_consent_record)
            .transpose()
    }

    async fn get_consent_records_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<ConsentRecord>> {
        sqlx::query_as::<_, DbConsentRecord>("SELECT * FROM consent_records WHERE license_id = $1")
            .bind(license_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(from_db_consent_record)
            .collect()
    }

    async fn create_license(&self, l: &License) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO licenses \
             (id, customer_id, product_id, bundle_version, connectivity_mode, seat_count, \
              expiry_at, status, superseded_by, revoked_at, revocation_reason, created_at, email_sent_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(l.id)
        .bind(l.customer_id)
        .bind(l.product_id)
        .bind(&l.bundle_version)
        .bind(encode_enum(&l.connectivity_mode))
        .bind(l.seat_count)
        .bind(l.expiry_at)
        .bind(encode_enum(&l.status))
        .bind(l.superseded_by)
        .bind(l.revoked_at)
        .bind(&l.revocation_reason)
        .bind(l.created_at)
        .bind(l.email_sent_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_license(&self, id: Uuid) -> crate::Result<Option<License>> {
        sqlx::query_as::<_, DbLicense>("SELECT * FROM licenses WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_license)
            .transpose()
    }

    async fn list_licenses_for_customer(&self, customer_id: Uuid) -> crate::Result<Vec<License>> {
        sqlx::query_as::<_, DbLicense>(
            "SELECT * FROM licenses WHERE customer_id = $1 ORDER BY created_at ASC",
        )
        .bind(customer_id)
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
        sqlx::query(
            "UPDATE licenses SET status = $1, revoked_at = $2, revocation_reason = $3, superseded_by = $4 WHERE id = $5",
        )
        .bind(encode_enum(&status))
        .bind(revoked_at)
        .bind(revocation_reason)
        .bind(superseded_by)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_license_email_sent(&self, id: Uuid, sent_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE licenses SET email_sent_at = $1 WHERE id = $2")
            .bind(sent_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl SeatStore for PostgresStorage {
    async fn create_seat_binding(&self, b: &FingerprintSeatBinding) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO fingerprint_seat_bindings \
             (id, license_id, fingerprint_commitment, seat_index, bound_at, last_verified_at, revoked_at, transfer_pending_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(b.id)
        .bind(b.license_id)
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
            "SELECT * FROM fingerprint_seat_bindings WHERE id = $1",
        )
        .bind(id)
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
            "SELECT * FROM fingerprint_seat_bindings WHERE license_id = $1 AND fingerprint_commitment = $2",
        )
        .bind(license_id)
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
            "SELECT * FROM fingerprint_seat_bindings WHERE license_id = $1",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_seat_binding)
        .collect()
    }

    async fn count_active_seat_bindings(&self, license_id: Uuid) -> crate::Result<u32> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM fingerprint_seat_bindings WHERE license_id = $1 AND revoked_at IS NULL",
        )
        .bind(license_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(u32::try_from(row.0)
            .map_err(|_| crate::Error::Corrupt("seat binding count out of u32 range".into()))?)
    }

    async fn revoke_seat_binding(&self, id: Uuid, revoked_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE fingerprint_seat_bindings SET revoked_at = $1 WHERE id = $2")
            .bind(revoked_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_seat_binding_verified(&self, id: Uuid, verified_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE fingerprint_seat_bindings SET last_verified_at = $1 WHERE id = $2")
            .bind(verified_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_issuance_secret(&self, s: &IssuanceSecret) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO issuance_secrets (license_id, secret, created_at) VALUES ($1,$2,$3)",
        )
        .bind(s.license_id)
        .bind(&s.secret)
        .bind(s.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_issuance_secret(&self, license_id: Uuid) -> crate::Result<Option<IssuanceSecret>> {
        sqlx::query_as::<_, DbIssuanceSecret>(
            "SELECT * FROM issuance_secrets WHERE license_id = $1",
        )
        .bind(license_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_issuance_secret)
        .transpose()
    }

    async fn delete_issuance_secret(&self, license_id: Uuid) -> crate::Result<()> {
        let result = sqlx::query("DELETE FROM issuance_secrets WHERE license_id = $1")
            .bind(license_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }

    async fn create_session(&self, s: &ActiveSession) -> crate::Result<()> {
        let seq_no = i64::try_from(s.seq_no)
            .map_err(|_| crate::Error::Corrupt("seq_no out of range".into()))?;
        let heartbeat_interval_secs = i32::try_from(s.heartbeat_interval_secs)
            .map_err(|_| crate::Error::Corrupt("heartbeat_interval_secs out of range".into()))?;
        let heartbeat_grace_secs = i32::try_from(s.heartbeat_grace_secs)
            .map_err(|_| crate::Error::Corrupt("heartbeat_grace_secs out of range".into()))?;
        let shutdown_countdown_secs = i32::try_from(s.shutdown_countdown_secs)
            .map_err(|_| crate::Error::Corrupt("shutdown_countdown_secs out of range".into()))?;
        sqlx::query(
            "INSERT INTO active_sessions \
             (id, binding_id, license_id, product_id, session_token, session_hmac_key_encrypted, \
              heartbeat_interval_secs, heartbeat_grace_secs, shutdown_countdown_secs, \
              seq_no, last_heartbeat_at, expires_at, status, command_pending, \
              created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(s.id)
        .bind(s.binding_id)
        .bind(s.license_id)
        .bind(s.product_id)
        .bind(s.session_token.as_ref())
        .bind(s.session_hmac_key_encrypted.as_ref())
        .bind(heartbeat_interval_secs)
        .bind(heartbeat_grace_secs)
        .bind(shutdown_countdown_secs)
        .bind(seq_no)
        .bind(s.last_heartbeat_at)
        .bind(s.expires_at)
        .bind(encode_enum(&s.status))
        .bind(s.command_pending.as_ref().map(encode_enum))
        .bind(s.created_at)
        .bind(s.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session(&self, id: Uuid) -> crate::Result<Option<ActiveSession>> {
        sqlx::query_as::<_, DbActiveSession>("SELECT * FROM active_sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_active_session)
            .transpose()
    }

    async fn get_active_or_suspect_session_for_binding(
        &self,
        binding_id: Uuid,
    ) -> crate::Result<Option<ActiveSession>> {
        sqlx::query_as::<_, DbActiveSession>(
            "SELECT * FROM active_sessions \
             WHERE binding_id = $1 AND status IN ('Active', 'Suspect') \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(binding_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_active_session)
        .transpose()
    }

    async fn update_active_session(
        &self,
        id: Uuid,
        expected_updated_at: i64,
        update: ActiveSessionUpdate,
    ) -> crate::Result<()> {
        use sqlx::QueryBuilder;
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("UPDATE active_sessions SET updated_at = ");
        qb.push_bind(update.updated_at);
        if let Some(token) = update.session_token {
            qb.push(", session_token = ").push_bind(token.to_vec());
        }
        if let Some(seq_no) = update.seq_no {
            let seq_no_i64 = i64::try_from(seq_no)
                .map_err(|_| crate::Error::Corrupt("seq_no out of range".into()))?;
            qb.push(", seq_no = ").push_bind(seq_no_i64);
        }
        if let Some(lha) = update.last_heartbeat_at {
            qb.push(", last_heartbeat_at = ").push_bind(lha);
        }
        if let Some(status) = update.status {
            qb.push(", status = ").push_bind(encode_enum(&status));
        }
        if let Some(cmd) = update.command_pending {
            qb.push(", command_pending = ")
                .push_bind(cmd.map(|c| encode_enum(&c)));
        }
        qb.push(" WHERE id = ").push_bind(id);
        qb.push(" AND updated_at = ").push_bind(expected_updated_at);
        let result = qb.build().execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }

    async fn expire_sessions_before(&self, expires_at: i64) -> crate::Result<u64> {
        let result = sqlx::query(
            "UPDATE active_sessions SET status = 'Expired' \
             WHERE expires_at < $1 AND status IN ('Active', 'Suspect')",
        )
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl PaymentStore for PostgresStorage {
    async fn create_payment_transaction(&self, t: &PaymentTransaction) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO payment_transactions \
             (id, license_id, provider, provider_transaction_id, amount, currency, \
              provider_tier, test_mode, status, created_at, confirmed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(t.id)
        .bind(t.license_id)
        .bind(encode_enum(&t.provider))
        .bind(&t.provider_transaction_id)
        .bind(t.amount)
        .bind(&t.currency)
        .bind(encode_enum(&t.provider_tier))
        .bind(t.test_mode)
        .bind(encode_enum(&t.status))
        .bind(t.created_at)
        .bind(t.confirmed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_payment_transaction(&self, id: Uuid) -> crate::Result<Option<PaymentTransaction>> {
        sqlx::query_as::<_, DbPaymentTransaction>(
            "SELECT * FROM payment_transactions WHERE id = $1",
        )
        .bind(id)
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
            "SELECT * FROM payment_transactions WHERE license_id = $1",
        )
        .bind(license_id)
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
        sqlx::query("UPDATE payment_transactions SET status = $1, confirmed_at = $2 WHERE id = $3")
            .bind(encode_enum(&status))
            .bind(confirmed_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_transfer_request(&self, r: &TransferRequest) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO transfer_requests \
             (id, license_id, old_fingerprint_commitment, new_fingerprint_commitment, \
              requested_at, status, vendor_note, resolved_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(r.id)
        .bind(r.license_id)
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
        sqlx::query_as::<_, DbTransferRequest>("SELECT * FROM transfer_requests WHERE id = $1")
            .bind(id)
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
            "SELECT * FROM transfer_requests WHERE license_id = $1 ORDER BY requested_at ASC",
        )
        .bind(license_id)
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
            "UPDATE transfer_requests SET status = $1, vendor_note = $2, resolved_at = $3 WHERE id = $4",
        )
        .bind(encode_enum(&status))
        .bind(vendor_note)
        .bind(resolved_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl SecurityStore for PostgresStorage {
    async fn create_quarantine_case(&self, c: &QuarantineCase) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO quarantine_cases \
             (id, case_id, binding_id, session_id, trigger, trigger_event_id, reason, \
              created_at, resumed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(c.id)
        .bind(c.case_id)
        .bind(c.binding_id)
        .bind(c.session_id)
        .bind(encode_enum(&c.trigger))
        .bind(c.trigger_event_id)
        .bind(&c.reason)
        .bind(c.created_at)
        .bind(c.resumed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_quarantine_case(&self, id: Uuid) -> crate::Result<Option<QuarantineCase>> {
        sqlx::query_as::<_, DbQuarantineCase>("SELECT * FROM quarantine_cases WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_quarantine_case)
            .transpose()
    }

    async fn get_quarantine_case_by_case_id(
        &self,
        case_id: Uuid,
    ) -> crate::Result<Option<QuarantineCase>> {
        sqlx::query_as::<_, DbQuarantineCase>("SELECT * FROM quarantine_cases WHERE case_id = $1")
            .bind(case_id)
            .fetch_optional(&self.pool)
            .await?
            .map(from_db_quarantine_case)
            .transpose()
    }

    async fn resume_quarantine_case(&self, id: Uuid, resumed_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE quarantine_cases SET resumed_at = $1 WHERE id = $2")
            .bind(resumed_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_active_quarantine_case_for_session(
        &self,
        session_id: Uuid,
    ) -> crate::Result<Option<QuarantineCase>> {
        sqlx::query_as::<_, DbQuarantineCase>(
            "SELECT * FROM quarantine_cases WHERE session_id = $1 AND resumed_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_quarantine_case)
        .transpose()
    }

    async fn get_active_quarantine_case_for_binding(
        &self,
        binding_id: Uuid,
    ) -> crate::Result<Option<QuarantineCase>> {
        sqlx::query_as::<_, DbQuarantineCase>(
            "SELECT * FROM quarantine_cases WHERE binding_id = $1 AND resumed_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(binding_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_quarantine_case)
        .transpose()
    }

    async fn create_security_event(&self, e: &SecurityEventRecord) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO security_events \
             (event_id, license_id, binding_id, session_id, occurred_at_ns, received_at_ns, \
              event_type, payload, severity, response_type, case_id, reviewed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(e.event_id)
        .bind(e.license_id)
        .bind(e.binding_id)
        .bind(e.session_id)
        .bind(e.occurred_at_ns)
        .bind(e.received_at_ns)
        .bind(&e.event_type)
        .bind(&e.payload)
        .bind(&e.severity)
        .bind(&e.response_type)
        .bind(e.case_id)
        .bind(e.reviewed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_security_event_by_event_id(
        &self,
        event_id: Uuid,
    ) -> crate::Result<Option<SecurityEventRecord>> {
        sqlx::query_as::<_, DbSecurityEventRecord>(
            "SELECT * FROM security_events WHERE event_id = $1",
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_security_event_record)
        .transpose()
    }

    async fn get_security_events_for_license(
        &self,
        license_id: Uuid,
    ) -> crate::Result<Vec<SecurityEventRecord>> {
        sqlx::query_as::<_, DbSecurityEventRecord>(
            "SELECT * FROM security_events WHERE license_id = $1 ORDER BY occurred_at_ns ASC",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_security_event_record)
        .collect()
    }

    async fn mark_security_event_reviewed(&self, id: i64, reviewed_at: i64) -> crate::Result<()> {
        sqlx::query("UPDATE security_events SET reviewed_at = $1 WHERE id = $2")
            .bind(reviewed_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_revocation_record(&self, r: &RevocationRecord) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO revocation_records (license_id, revoked_at, revoked_by, reason) VALUES ($1,$2,$3,$4)",
        )
        .bind(r.license_id)
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
            "SELECT * FROM revocation_records WHERE license_id = $1",
        )
        .bind(license_id)
        .fetch_optional(&self.pool)
        .await?
        .map(from_db_revocation_record)
        .transpose()
    }

    async fn create_email_log_entry(&self, e: &EmailLogEntry) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO email_log (id, license_id, email_type, sent_to, sent_at, success, error_message) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(e.id)
        .bind(e.license_id)
        .bind(encode_enum(&e.email_type))
        .bind(&e.sent_to)
        .bind(e.sent_at)
        .bind(e.success)
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
            "SELECT * FROM email_log WHERE license_id = $1 ORDER BY sent_at ASC",
        )
        .bind(license_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(from_db_email_log_entry)
        .collect()
    }
}

#[async_trait]
impl EnrollmentStore for PostgresStorage {
    async fn count_transferable_seat_bindings(&self, product_id: Uuid) -> crate::Result<u32> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM fingerprint_seat_bindings fsb \
             JOIN licenses l ON l.id = fsb.license_id \
             WHERE l.product_id = $1 AND fsb.revoked_at IS NULL AND fsb.transfer_pending_at IS NULL",
        )
        .bind(product_id)
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
        sqlx::query("UPDATE fingerprint_seat_bindings SET transfer_pending_at = $1 WHERE id = $2")
            .bind(pending_at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_enrollment_session(&self, s: &EnrollmentSession) -> crate::Result<()> {
        sqlx::query(
            "INSERT INTO enrollment_sessions \
             (id, product_id, fingerprint_commitment, customer_pubkey, client_version, \
              protocol_version, state, offer_nonce, offer_expires_at, terms_document_id, \
              request_bytes, offer_bytes, receipt_bytes, payment_intent_id, payment_captured, \
              grant_bytes, transfer_request_id, license_id, abandon_reason, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
        )
        .bind(s.id)
        .bind(s.product_id)
        .bind(&s.fingerprint_commitment)
        .bind(&s.customer_pubkey)
        .bind(&s.client_version)
        .bind(s.protocol_version)
        .bind(encode_enum(&s.state))
        .bind(&s.offer_nonce)
        .bind(s.offer_expires_at)
        .bind(s.terms_document_id)
        .bind(&s.request_bytes)
        .bind(&s.offer_bytes)
        .bind(&s.receipt_bytes)
        .bind(&s.payment_intent_id)
        .bind(s.payment_captured)
        .bind(&s.grant_bytes)
        .bind(s.transfer_request_id)
        .bind(s.license_id)
        .bind(&s.abandon_reason)
        .bind(s.created_at)
        .bind(s.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_enrollment_session(&self, id: Uuid) -> crate::Result<Option<EnrollmentSession>> {
        sqlx::query_as::<_, DbEnrollmentSession>("SELECT * FROM enrollment_sessions WHERE id = $1")
            .bind(id)
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
            "SELECT * FROM enrollment_sessions WHERE payment_intent_id = $1",
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
        let mut sets: Vec<String> = Vec::new();
        let mut param_idx: u32 = 1;

        if update.state.is_some() {
            sets.push(format!("state = ${param_idx}"));
            param_idx += 1;
        }
        if update.receipt_bytes.is_some() {
            sets.push(format!("receipt_bytes = ${param_idx}"));
            param_idx += 1;
        }
        if update.payment_intent_id.is_some() {
            sets.push(format!("payment_intent_id = ${param_idx}"));
            param_idx += 1;
        }
        if update.payment_captured.is_some() {
            sets.push(format!("payment_captured = ${param_idx}"));
            param_idx += 1;
        }
        if update.grant_bytes.is_some() {
            sets.push(format!("grant_bytes = ${param_idx}"));
            param_idx += 1;
        }
        if update.license_id.is_some() {
            sets.push(format!("license_id = ${param_idx}"));
            param_idx += 1;
        }
        if update.abandon_reason.is_some() {
            sets.push(format!("abandon_reason = ${param_idx}"));
            param_idx += 1;
        }
        sets.push(format!("updated_at = ${param_idx}"));
        param_idx += 1;

        let sql = format!(
            "UPDATE enrollment_sessions SET {} WHERE id = ${} AND (updated_at = ${} OR ${} = 0)",
            sets.join(", "),
            param_idx,
            param_idx + 1,
            param_idx + 2,
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
            q = q.bind(v);
        }
        if let Some(v) = update.grant_bytes {
            q = q.bind(v);
        }
        if let Some(v) = update.license_id {
            q = q.bind(v);
        }
        if let Some(v) = update.abandon_reason {
            q = q.bind(v);
        }
        q = q.bind(update.updated_at);
        q = q.bind(id);
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
