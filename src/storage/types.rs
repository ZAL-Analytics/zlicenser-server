use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityMode {
    AirGapped,
    Online,
    AlwaysOnline,
}

impl std::fmt::Display for ConnectivityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AirGapped => "AirGapped",
            Self::Online => "Online",
            Self::AlwaysOnline => "AlwaysOnline",
        })
    }
}

impl std::str::FromStr for ConnectivityMode {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "AirGapped" => Ok(Self::AirGapped),
            "Online" => Ok(Self::Online),
            "AlwaysOnline" => Ok(Self::AlwaysOnline),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown ConnectivityMode: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsaTier {
    Free,
    Standard,
    Qualified,
}

impl std::fmt::Display for TsaTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Free => "Free",
            Self::Standard => "Standard",
            Self::Qualified => "Qualified",
        })
    }
}

impl std::str::FromStr for TsaTier {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Free" => Ok(Self::Free),
            "Standard" => Ok(Self::Standard),
            "Qualified" => Ok(Self::Qualified),
            _ => Err(crate::Error::Corrupt(format!("unknown TsaTier: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferPolicy {
    NotAvailable,
    VendorApproval,
}

impl std::fmt::Display for TransferPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotAvailable => "NotAvailable",
            Self::VendorApproval => "VendorApproval",
        })
    }
}

impl std::str::FromStr for TransferPolicy {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "NotAvailable" => Ok(Self::NotAvailable),
            "VendorApproval" => Ok(Self::VendorApproval),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown TransferPolicy: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermsValidationStatus {
    Valid,
    Warnings,
    Conflicts,
    PendingReview,
}

impl std::fmt::Display for TermsValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Valid => "Valid",
            Self::Warnings => "Warnings",
            Self::Conflicts => "Conflicts",
            Self::PendingReview => "PendingReview",
        })
    }
}

impl std::str::FromStr for TermsValidationStatus {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Valid" => Ok(Self::Valid),
            "Warnings" => Ok(Self::Warnings),
            "Conflicts" => Ok(Self::Conflicts),
            "PendingReview" => Ok(Self::PendingReview),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown TermsValidationStatus: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    Active,
    Revoked,
    Superseded,
}

impl std::fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "Active",
            Self::Revoked => "Revoked",
            Self::Superseded => "Superseded",
        })
    }
}

impl std::str::FromStr for LicenseStatus {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Active" => Ok(Self::Active),
            "Revoked" => Ok(Self::Revoked),
            "Superseded" => Ok(Self::Superseded),
            _ => Err(crate::Error::Corrupt(format!("unknown LicenseStatus: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentProvider {
    Stripe,
    Custom,
}

impl std::fmt::Display for PaymentProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stripe => "Stripe",
            Self::Custom => "Custom",
        })
    }
}

impl std::str::FromStr for PaymentProvider {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Stripe" => Ok(Self::Stripe),
            "Custom" => Ok(Self::Custom),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown PaymentProvider: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    Pending,
    Confirmed,
    Failed,
}

impl std::fmt::Display for PaymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending => "Pending",
            Self::Confirmed => "Confirmed",
            Self::Failed => "Failed",
        })
    }
}

impl std::str::FromStr for PaymentStatus {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Confirmed" => Ok(Self::Confirmed),
            "Failed" => Ok(Self::Failed),
            _ => Err(crate::Error::Corrupt(format!("unknown PaymentStatus: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTier {
    Verified,
    Pseudonymous,
    Anonymous,
}

impl std::fmt::Display for ProviderTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Verified => "Verified",
            Self::Pseudonymous => "Pseudonymous",
            Self::Anonymous => "Anonymous",
        })
    }
}

impl std::str::FromStr for ProviderTier {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Verified" => Ok(Self::Verified),
            "Pseudonymous" => Ok(Self::Pseudonymous),
            "Anonymous" => Ok(Self::Anonymous),
            _ => Err(crate::Error::Corrupt(format!("unknown ProviderTier: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Pending,
    Approved,
    Rejected,
}

impl std::fmt::Display for TransferStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Rejected => "Rejected",
        })
    }
}

impl std::str::FromStr for TransferStatus {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Approved" => Ok(Self::Approved),
            "Rejected" => Ok(Self::Rejected),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown TransferStatus: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Suspect,
    Quarantined,
    Expired,
    Terminated,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "Active",
            Self::Suspect => "Suspect",
            Self::Quarantined => "Quarantined",
            Self::Expired => "Expired",
            Self::Terminated => "Terminated",
        })
    }
}

impl std::str::FromStr for SessionStatus {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Active" => Ok(Self::Active),
            "Suspect" => Ok(Self::Suspect),
            "Quarantined" => Ok(Self::Quarantined),
            "Expired" => Ok(Self::Expired),
            "Terminated" => Ok(Self::Terminated),
            _ => Err(crate::Error::Corrupt(format!("unknown SessionStatus: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineTrigger {
    MissedHeartbeat,
    SecurityEvent,
    VendorAction,
}

impl std::fmt::Display for QuarantineTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissedHeartbeat => "MissedHeartbeat",
            Self::SecurityEvent => "SecurityEvent",
            Self::VendorAction => "VendorAction",
        })
    }
}

impl std::str::FromStr for QuarantineTrigger {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "MissedHeartbeat" => Ok(Self::MissedHeartbeat),
            "SecurityEvent" => Ok(Self::SecurityEvent),
            "VendorAction" => Ok(Self::VendorAction),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown QuarantineTrigger: {s}"
            ))),
        }
    }
}

/// Vendor dashboard action queued for delivery on the next heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingCommand {
    Resume,
    Terminate,
}

impl std::fmt::Display for PendingCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Resume => "Resume",
            Self::Terminate => "Terminate",
        })
    }
}

impl std::str::FromStr for PendingCommand {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Resume" => Ok(Self::Resume),
            "Terminate" => Ok(Self::Terminate),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown PendingCommand: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSource {
    VendorDashboard,
    Api,
}

impl std::fmt::Display for RevocationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::VendorDashboard => "VendorDashboard",
            Self::Api => "API",
        })
    }
}

impl std::str::FromStr for RevocationSource {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "VendorDashboard" => Ok(Self::VendorDashboard),
            "API" => Ok(Self::Api),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown RevocationSource: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdprBasis {
    Contract,
    LegalObligation,
    LegitimateInterest,
}

impl std::fmt::Display for GdprBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Contract => "Contract",
            Self::LegalObligation => "LegalObligation",
            Self::LegitimateInterest => "LegitimateInterest",
        })
    }
}

impl std::str::FromStr for GdprBasis {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Contract" => Ok(Self::Contract),
            "LegalObligation" => Ok(Self::LegalObligation),
            "LegitimateInterest" => Ok(Self::LegitimateInterest),
            _ => Err(crate::Error::Corrupt(format!("unknown GdprBasis: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradePolicy {
    AutoApprove,
    RequireNewPurchase,
    FreeUpgrade,
}

impl std::fmt::Display for UpgradePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AutoApprove => "AutoApprove",
            Self::RequireNewPurchase => "RequireNewPurchase",
            Self::FreeUpgrade => "FreeUpgrade",
        })
    }
}

impl std::str::FromStr for UpgradePolicy {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "AutoApprove" => Ok(Self::AutoApprove),
            "RequireNewPurchase" => Ok(Self::RequireNewPurchase),
            "FreeUpgrade" => Ok(Self::FreeUpgrade),
            _ => Err(crate::Error::Corrupt(format!("unknown UpgradePolicy: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailType {
    GrantConfirmation,
}

impl std::fmt::Display for EmailType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::GrantConfirmation => "GrantConfirmation",
        })
    }
}

impl std::str::FromStr for EmailType {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "GrantConfirmation" => Ok(Self::GrantConfirmation),
            _ => Err(crate::Error::Corrupt(format!("unknown EmailType: {s}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VendorConfig {
    pub id: i64,
    pub public_key: Vec<u8>,
    pub public_key_fingerprint: String,
    pub registered_at: i64,
    pub rotated_from_key: Option<Vec<u8>>,
    pub rotated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Product {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub connectivity_mode: ConnectivityMode,
    pub seat_count: i64,
    pub expiry_policy: String,
    pub grace_period_days: Option<i64>,
    pub heartbeat_interval_secs: Option<i64>,
    pub heartbeat_grace_secs: Option<i64>,
    pub shutdown_countdown_secs: Option<i64>,
    pub auto_quarantine_on_critical: bool,
    pub tsa_tier: TsaTier,
    pub bundle_version: String,
    pub transfer_policy: TransferPolicy,
    pub pricing_amount: i64,
    pub pricing_currency: String,
    pub payment_provider: PaymentProvider,
    pub min_client_version_warning: Option<String>,
    pub min_client_version_required: Option<String>,
    pub active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProductTermDeclaration {
    pub product_id: Uuid,
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

#[derive(Debug, Clone, PartialEq)]
pub struct ProductTermsDocument {
    pub id: Uuid,
    pub product_id: Uuid,
    pub typst_source: String,
    pub rendered_hash: String,
    pub validation_status: TermsValidationStatus,
    pub validation_findings: String,
    pub vendor_acknowledged_at: Option<i64>,
    pub vendor_acknowledged_findings: Option<String>,
    pub activated_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProductCustomerField {
    pub id: Uuid,
    pub product_id: Uuid,
    pub field_key: String,
    pub required: bool,
    pub gdpr_basis: GdprBasis,
    pub purpose_description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpgradePolicyRow {
    pub id: Uuid,
    pub product_id: Uuid,
    pub from_version: String,
    pub to_version: String,
    pub policy: UpgradePolicy,
    /// Unix nanoseconds; used as a tie-breaking key when two policies have equal specificity.
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Customer {
    pub id: Uuid,
    pub product_id: Uuid,
    pub full_name: String,
    pub email: String,
    pub field_values: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConsentRecord {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub license_id: Uuid,
    pub terms_document_id: Uuid,
    pub terms_rendered_hash: String,
    pub checkboxes_ticked: String,
    pub accepted_at_ns: i64,
    pub ip_address: String,
    pub client_version: String,
    pub protocol_version: i64,
    pub terms_findings_shown: String,
    pub payment_provider: PaymentProvider,
    pub payment_provider_tier: ProviderTier,
}

#[derive(Debug, Clone, PartialEq)]
pub struct License {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub product_id: Uuid,
    pub bundle_version: String,
    pub connectivity_mode: ConnectivityMode,
    pub seat_count: i64,
    pub expiry_at: Option<i64>,
    pub status: LicenseStatus,
    pub superseded_by: Option<Uuid>,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<String>,
    pub created_at: i64,
    pub email_sent_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FingerprintSeatBinding {
    pub id: Uuid,
    pub license_id: Uuid,
    pub fingerprint_commitment: Vec<u8>,
    pub seat_index: i64,
    pub bound_at: i64,
    pub last_verified_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub transfer_pending_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssuanceSecret {
    pub license_id: Uuid,
    pub secret: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaymentTransaction {
    pub id: Uuid,
    pub license_id: Uuid,
    pub provider: PaymentProvider,
    pub provider_transaction_id: String,
    pub amount: i64,
    pub currency: String,
    pub provider_tier: ProviderTier,
    pub payment_sandbox: bool,
    pub status: PaymentStatus,
    pub created_at: i64,
    pub confirmed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransferRequest {
    pub id: Uuid,
    pub license_id: Uuid,
    pub old_fingerprint_commitment: Vec<u8>,
    pub new_fingerprint_commitment: Vec<u8>,
    pub requested_at: i64,
    pub status: TransferStatus,
    pub vendor_note: Option<String>,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveSession {
    pub id: Uuid,
    pub binding_id: Uuid,
    pub license_id: Uuid,
    pub product_id: Uuid,
    /// Rolling 32-byte authentication token; rotated on every `HeartbeatAck`.
    pub session_token: [u8; 32],
    /// AES-256-GCM encrypted HMAC key: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
    pub session_hmac_key_encrypted: [u8; 60],
    pub heartbeat_interval_secs: u32,
    pub heartbeat_grace_secs: u32,
    pub shutdown_countdown_secs: u32,
    pub seq_no: u64,
    pub last_heartbeat_at: Option<i64>,
    pub expires_at: i64,
    pub status: SessionStatus,
    pub command_pending: Option<PendingCommand>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Partial-update builder used by session handlers to avoid full re-writes.
#[derive(Default)]
pub struct ActiveSessionUpdate {
    pub session_token: Option<[u8; 32]>,
    pub seq_no: Option<u64>,
    pub last_heartbeat_at: Option<i64>,
    pub status: Option<SessionStatus>,
    pub command_pending: Option<Option<PendingCommand>>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuarantineCase {
    pub id: Uuid,
    /// Stable external identifier included in signed commands delivered to the shim.
    pub case_id: Uuid,
    pub binding_id: Uuid,
    pub session_id: Option<Uuid>,
    pub trigger: QuarantineTrigger,
    /// UUID of the `SecurityEventRecord` that triggered this case, if any.
    pub trigger_event_id: Option<Uuid>,
    pub reason: String,
    pub created_at: i64,
    pub resumed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEventRecord {
    pub id: i64,
    pub event_id: Uuid,
    pub license_id: Uuid,
    pub binding_id: Uuid,
    pub session_id: Option<Uuid>,
    pub occurred_at_ns: i64,
    pub received_at_ns: i64,
    /// Serialized `SecurityEventType` tag, e.g. `"DebuggerDetected"`.
    pub event_type: String,
    /// Full JSON payload of the `SecurityEventType` variant.
    pub payload: String,
    pub severity: String,
    /// Which `SecurityResponse` variant was returned: `"Log" | "Warn" | "Quarantine" | "Terminate"`.
    pub response_type: String,
    pub case_id: Option<Uuid>,
    pub reviewed_at: Option<i64>,
    pub false_positive_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevocationRecord {
    pub license_id: Uuid,
    pub revoked_at: i64,
    pub revoked_by: RevocationSource,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmailLogEntry {
    pub id: Uuid,
    pub license_id: Uuid,
    pub email_type: EmailType,
    pub sent_to: String,
    pub sent_at: i64,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    OfferPending,
    ReceiptPending,
    PaymentHeld,
    TSAPending,
    GrantReady,
    Issued,
    Abandoned,
}

impl std::fmt::Display for EnrollmentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OfferPending => "OfferPending",
            Self::ReceiptPending => "ReceiptPending",
            Self::PaymentHeld => "PaymentHeld",
            Self::TSAPending => "TSAPending",
            Self::GrantReady => "GrantReady",
            Self::Issued => "Issued",
            Self::Abandoned => "Abandoned",
        })
    }
}

impl std::str::FromStr for EnrollmentState {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "OfferPending" => Ok(Self::OfferPending),
            "ReceiptPending" => Ok(Self::ReceiptPending),
            "PaymentHeld" => Ok(Self::PaymentHeld),
            "TSAPending" => Ok(Self::TSAPending),
            "GrantReady" => Ok(Self::GrantReady),
            "Issued" => Ok(Self::Issued),
            "Abandoned" => Ok(Self::Abandoned),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown EnrollmentState: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EnrollmentSession {
    pub id: Uuid,
    pub product_id: Uuid,
    pub fingerprint_commitment: Vec<u8>,
    pub customer_pubkey: Vec<u8>,
    pub client_version: String,
    pub protocol_version: i64,
    pub state: EnrollmentState,
    pub offer_nonce: Option<Vec<u8>>,
    pub offer_expires_at: Option<i64>,
    pub terms_document_id: Option<Uuid>,
    pub request_bytes: Vec<u8>,
    pub offer_bytes: Option<Vec<u8>>,
    pub receipt_bytes: Option<Vec<u8>>,
    pub payment_intent_id: Option<String>,
    pub payment_captured: bool,
    pub grant_bytes: Option<Vec<u8>>,
    pub transfer_request_id: Option<Uuid>,
    pub license_id: Option<Uuid>,
    pub abandon_reason: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Default)]
pub struct EnrollmentSessionUpdate {
    pub state: Option<EnrollmentState>,
    pub receipt_bytes: Option<Vec<u8>>,
    pub payment_intent_id: Option<String>,
    pub payment_captured: Option<bool>,
    pub grant_bytes: Option<Vec<u8>>,
    pub license_id: Option<Option<Uuid>>,
    pub abandon_reason: Option<String>,
    pub updated_at: i64,
}

pub mod abandon_reason {
    pub const OFFER_EXPIRED: &str = "OfferExpired";
    pub const PAYMENT_FAILED: &str = "PaymentFailed";
    pub const TSA_FAILED: &str = "TsaFailed";
    pub const CAPTURE_FAILED: &str = "CaptureFailed";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Support,
    ProductManager,
    Auditor,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Support => "Support",
            Self::ProductManager => "ProductManager",
            Self::Auditor => "Auditor",
        })
    }
}

impl std::str::FromStr for Role {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Owner" => Ok(Self::Owner),
            "Admin" => Ok(Self::Admin),
            "Support" => Ok(Self::Support),
            "ProductManager" => Ok(Self::ProductManager),
            "Auditor" => Ok(Self::Auditor),
            _ => Err(crate::Error::Corrupt(format!("unknown Role: {s}"))),
        }
    }
}

pub struct StaffUser {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub display_name: String,
    pub role: Role,
    pub active: bool,
    pub created_by: Option<Uuid>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewStaffUser {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub display_name: String,
    pub role: Role,
    pub created_by: Option<Uuid>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct StaffUserUpdate {
    pub display_name: Option<String>,
    pub role: Option<Role>,
    pub active: Option<bool>,
    pub password_hash: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAuthMethod {
    KeyBased,
    Password,
    Cli,
}

impl std::fmt::Display for AuditAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::KeyBased => "KeyBased",
            Self::Password => "Password",
            Self::Cli => "CLI",
        })
    }
}

impl std::str::FromStr for AuditAuthMethod {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "KeyBased" => Ok(Self::KeyBased),
            "Password" => Ok(Self::Password),
            "CLI" => Ok(Self::Cli),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown AuditAuthMethod: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    LoginSuccess,
    LoginFailed,
    Logout,
    ProductCreate,
    ProductUpdate,
    ProductDelete,
    ProductActivate,
    DeclarationsUpdate,
    TermsDocumentUpload,
    TermsDocumentAcknowledge,
    CustomerFieldsUpdate,
    BundleVersionUpdate,
    UpgradePolicyCreate,
    UpgradePolicyDelete,
    LicenseRevoke,
    CustomerRevokeAll,
    TransferApprove,
    TransferReject,
    SecurityEventReview,
    SecurityEventFalsePositive,
    BindingQuarantine,
    BindingTerminate,
    BindingResume,
    UserCreate,
    UserRoleChange,
    UserDeactivate,
    UserReactivate,
    OwnPasswordChange,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LoginSuccess => "LoginSuccess",
            Self::LoginFailed => "LoginFailed",
            Self::Logout => "Logout",
            Self::ProductCreate => "ProductCreate",
            Self::ProductUpdate => "ProductUpdate",
            Self::ProductDelete => "ProductDelete",
            Self::ProductActivate => "ProductActivate",
            Self::DeclarationsUpdate => "DeclarationsUpdate",
            Self::TermsDocumentUpload => "TermsDocumentUpload",
            Self::TermsDocumentAcknowledge => "TermsDocumentAcknowledge",
            Self::CustomerFieldsUpdate => "CustomerFieldsUpdate",
            Self::BundleVersionUpdate => "BundleVersionUpdate",
            Self::UpgradePolicyCreate => "UpgradePolicyCreate",
            Self::UpgradePolicyDelete => "UpgradePolicyDelete",
            Self::LicenseRevoke => "LicenseRevoke",
            Self::CustomerRevokeAll => "CustomerRevokeAll",
            Self::TransferApprove => "TransferApprove",
            Self::TransferReject => "TransferReject",
            Self::SecurityEventReview => "SecurityEventReview",
            Self::SecurityEventFalsePositive => "SecurityEventFalsePositive",
            Self::BindingQuarantine => "BindingQuarantine",
            Self::BindingTerminate => "BindingTerminate",
            Self::BindingResume => "BindingResume",
            Self::UserCreate => "UserCreate",
            Self::UserRoleChange => "UserRoleChange",
            Self::UserDeactivate => "UserDeactivate",
            Self::UserReactivate => "UserReactivate",
            Self::OwnPasswordChange => "OwnPasswordChange",
        })
    }
}

impl std::str::FromStr for AuditAction {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "LoginSuccess" => Ok(Self::LoginSuccess),
            "LoginFailed" => Ok(Self::LoginFailed),
            "Logout" => Ok(Self::Logout),
            "ProductCreate" => Ok(Self::ProductCreate),
            "ProductUpdate" => Ok(Self::ProductUpdate),
            "ProductDelete" => Ok(Self::ProductDelete),
            "ProductActivate" => Ok(Self::ProductActivate),
            "DeclarationsUpdate" => Ok(Self::DeclarationsUpdate),
            "TermsDocumentUpload" => Ok(Self::TermsDocumentUpload),
            "TermsDocumentAcknowledge" => Ok(Self::TermsDocumentAcknowledge),
            "CustomerFieldsUpdate" => Ok(Self::CustomerFieldsUpdate),
            "BundleVersionUpdate" => Ok(Self::BundleVersionUpdate),
            "UpgradePolicyCreate" => Ok(Self::UpgradePolicyCreate),
            "UpgradePolicyDelete" => Ok(Self::UpgradePolicyDelete),
            "LicenseRevoke" => Ok(Self::LicenseRevoke),
            "CustomerRevokeAll" => Ok(Self::CustomerRevokeAll),
            "TransferApprove" => Ok(Self::TransferApprove),
            "TransferReject" => Ok(Self::TransferReject),
            "SecurityEventReview" => Ok(Self::SecurityEventReview),
            "SecurityEventFalsePositive" => Ok(Self::SecurityEventFalsePositive),
            "BindingQuarantine" => Ok(Self::BindingQuarantine),
            "BindingTerminate" => Ok(Self::BindingTerminate),
            "BindingResume" => Ok(Self::BindingResume),
            "UserCreate" => Ok(Self::UserCreate),
            "UserRoleChange" => Ok(Self::UserRoleChange),
            "UserDeactivate" => Ok(Self::UserDeactivate),
            "UserReactivate" => Ok(Self::UserReactivate),
            "OwnPasswordChange" => Ok(Self::OwnPasswordChange),
            _ => Err(crate::Error::Corrupt(format!("unknown AuditAction: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditTargetType {
    Product,
    TermsDocument,
    Customer,
    License,
    Transfer,
    SecurityEvent,
    Binding,
    Vendor,
    Auth,
    User,
}

impl std::fmt::Display for AuditTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Product => "product",
            Self::TermsDocument => "terms_document",
            Self::Customer => "customer",
            Self::License => "license",
            Self::Transfer => "transfer",
            Self::SecurityEvent => "security_event",
            Self::Binding => "binding",
            Self::Vendor => "vendor",
            Self::Auth => "auth",
            Self::User => "user",
        })
    }
}

impl std::str::FromStr for AuditTargetType {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "product" => Ok(Self::Product),
            "terms_document" => Ok(Self::TermsDocument),
            "customer" => Ok(Self::Customer),
            "license" => Ok(Self::License),
            "transfer" => Ok(Self::Transfer),
            "security_event" => Ok(Self::SecurityEvent),
            "binding" => Ok(Self::Binding),
            "vendor" => Ok(Self::Vendor),
            "auth" => Ok(Self::Auth),
            "user" => Ok(Self::User),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown AuditTargetType: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub id: Uuid,
    pub occurred_at: i64,
    pub auth_method: AuditAuthMethod,
    pub action: AuditAction,
    pub target_type: AuditTargetType,
    pub target_id: Option<Uuid>,
    pub detail: Option<String>,
    pub actor_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub action: Option<AuditAction>,
    pub target_id: Option<Uuid>,
    pub from_ns: Option<i64>,
    pub to_ns: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub page: u32,
    pub page_size: u32,
}

impl Page {
    pub fn new(page: u32, page_size: u32) -> Self {
        Self {
            page: page.max(1),
            page_size: page_size.clamp(1, 200),
        }
    }

    pub fn offset(self) -> i64 {
        i64::from((self.page - 1) * self.page_size)
    }

    pub fn limit(self) -> i64 {
        i64::from(self.page_size)
    }
}

impl Default for Page {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 50,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct LicenseFilter {
    pub product_id: Option<Uuid>,
    pub status: Option<LicenseStatus>,
    pub mode: Option<ConnectivityMode>,
    pub search: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityEventFilter {
    pub license_id: Option<Uuid>,
    pub binding_id: Option<Uuid>,
    pub product_id: Option<Uuid>,
}
