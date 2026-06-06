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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineStatus {
    Active,
    Resolved,
}

impl std::fmt::Display for QuarantineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "Active",
            Self::Resolved => "Resolved",
        })
    }
}

impl std::str::FromStr for QuarantineStatus {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Active" => Ok(Self::Active),
            "Resolved" => Ok(Self::Resolved),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown QuarantineStatus: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for SecurityEventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
        })
    }
}

impl std::str::FromStr for SecurityEventSeverity {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Info" => Ok(Self::Info),
            "Warning" => Ok(Self::Warning),
            "Critical" => Ok(Self::Critical),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown SecurityEventSeverity: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventResponse {
    Log,
    Warn,
    Quarantine,
    Terminate,
}

impl std::fmt::Display for SecurityEventResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Log => "Log",
            Self::Warn => "Warn",
            Self::Quarantine => "Quarantine",
            Self::Terminate => "Terminate",
        })
    }
}

impl std::str::FromStr for SecurityEventResponse {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s {
            "Log" => Ok(Self::Log),
            "Warn" => Ok(Self::Warn),
            "Quarantine" => Ok(Self::Quarantine),
            "Terminate" => Ok(Self::Terminate),
            _ => Err(crate::Error::Corrupt(format!(
                "unknown SecurityEventResponse: {s}"
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpgradePolicyRow {
    pub id: Uuid,
    pub product_id: Uuid,
    pub from_version: String,
    pub to_version: String,
    pub policy: UpgradePolicy,
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
    pub test_mode: bool,
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
    pub ephemeral_pubkey: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub last_heartbeat_at: Option<i64>,
    pub seq_no: i64,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuarantineCase {
    pub id: Uuid,
    pub case_id: Uuid,
    pub binding_id: Uuid,
    pub session_id: Option<Uuid>,
    pub trigger: QuarantineTrigger,
    pub triggered_at: i64,
    pub status: QuarantineStatus,
    pub resolution: Option<String>,
    pub resolved_at: Option<i64>,
    pub vendor_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    pub id: i64,
    pub event_id: Uuid,
    pub license_id: Uuid,
    pub binding_id: Uuid,
    pub session_id: Option<Uuid>,
    pub occurred_at_ns: i64,
    pub received_at_ns: i64,
    pub event_type: String,
    pub severity: SecurityEventSeverity,
    pub payload: String,
    pub response: SecurityEventResponse,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<i64>,
    pub case_id: Option<Uuid>,
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
