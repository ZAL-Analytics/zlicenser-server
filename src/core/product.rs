use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;
use zlicenser_protocol::terms::{
    ConnectivityDeclaration, ExpiryDeclaration, RefundDeclaration, RevocationDeclaration,
    SupportScope, TermDeclarations, TermsValidationReport, TransferDeclaration, UpdatesPolicy,
    ValidationStatus, WarrantyDeclaration, generate_template, validate_terms,
};

use crate::{
    Error,
    storage::{
        ConnectivityMode, GdprBasis, Product, ProductCustomerField, ProductTermDeclaration,
        ProductTermsDocument, TermsValidationStatus, TransferPolicy, UpgradePolicy,
        UpgradePolicyRow, VendorStore,
    },
};

// Constants
const KNOWN_FIELD_KEYS: &[&str] = &[
    "phone",
    "address",
    "company_name",
    "eu_vat_number",
    "chamber_of_commerce",
    "date_of_birth",
    "national_id",
    "nationality",
    "industry",
    "student_id",
];

const EU_MEMBER_STATE_CODES: &[&str] = &[
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT",
    "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
];

#[rustfmt::skip]
const ISO_3166_1_ALPHA2: &[&str] = &[
    "AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT","AZ",
    "BS","BH","BD","BB","BY","BE","BZ","BJ","BM","BT","BO","BQ","BA","BW","BV","BR","IO","BN","BG","BF","BI",
    "CV","KH","CM","CA","KY","CF","TD","CL","CN","CX","CC","CO","KM","CD","CG","CK","CR","HR","CU","CW","CY","CZ",
    "DK","DJ","DM","DO",
    "EC","EG","SV","GQ","ER","EE","SZ","ET",
    "FK","FO","FJ","FI","FR","GF","PF","TF",
    "GA","GM","GE","DE","GH","GI","GR","GL","GD","GP","GU","GT","GG","GN","GW","GY",
    "HT","HM","VA","HN","HK","HU",
    "IS","IN","ID","IR","IQ","IE","IM","IL","IT",
    "JM","JP","JE","JO",
    "KZ","KE","KI","KP","KR","KW","KG",
    "LA","LV","LB","LS","LR","LY","LI","LT","LU",
    "MO","MG","MW","MY","MV","ML","MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS","MA","MZ","MM",
    "NA","NR","NP","NL","NC","NZ","NI","NE","NG","NU","NF","MK","MP","NO",
    "OM",
    "PK","PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR",
    "QA",
    "RE","RO","RU","RW",
    "BL","SH","KN","LC","MF","PM","VC","WS","SM","ST","SA","SN","RS","SC","SL","SG","SX","SK","SI","SB","SO","ZA","GS","SS","ES","LK","SD","SR","SJ","SE","CH","SY",
    "TW","TJ","TZ","TH","TL","TG","TK","TO","TT","TN","TR","TM","TC","TV",
    "UG","UA","AE","GB","UM","US","UY","UZ",
    "VU","VE","VN","VG","VI",
    "WF",
    "EH",
    "YE",
    "ZM","ZW",
];

// Private helpers
fn connectivity_from_mode(mode: ConnectivityMode) -> ConnectivityDeclaration {
    match mode {
        ConnectivityMode::AirGapped => ConnectivityDeclaration::AirGapped,
        ConnectivityMode::Online => ConnectivityDeclaration::Online,
        ConnectivityMode::AlwaysOnline => ConnectivityDeclaration::AlwaysOnline,
    }
}

fn transfer_from_policy(policy: TransferPolicy) -> TransferDeclaration {
    match policy {
        TransferPolicy::NotAvailable => TransferDeclaration::NotAvailable,
        TransferPolicy::VendorApproval => TransferDeclaration::VendorApproval,
    }
}

fn map_validation_status(s: ValidationStatus) -> TermsValidationStatus {
    match s {
        ValidationStatus::Valid => TermsValidationStatus::Valid,
        ValidationStatus::Warnings => TermsValidationStatus::Warnings,
        ValidationStatus::Conflicts => TermsValidationStatus::Conflicts,
    }
}

fn current_year() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let year = 1970_u64 + secs / 31_557_600;
    u32::try_from(year).unwrap_or(u32::MAX)
}

fn validate_phone(value: &str) -> crate::Result<()> {
    let digits = value
        .strip_prefix('+')
        .ok_or_else(|| Error::InvalidFieldValue {
            field: "phone".to_owned(),
            reason: "must start with '+'".to_owned(),
        })?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidFieldValue {
            field: "phone".to_owned(),
            reason: "digits after '+' must all be 0–9".to_owned(),
        });
    }
    // E.164: + followed by 7–15 digits = total length 8–16
    if value.len() < 8 || value.len() > 16 {
        return Err(Error::InvalidFieldValue {
            field: "phone".to_owned(),
            reason: format!("E.164 number must be 8–16 chars total, got {}", value.len()),
        });
    }
    Ok(())
}

fn validate_address(value: &str) -> crate::Result<()> {
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| Error::InvalidFieldValue {
            field: "address".to_owned(),
            reason: "must be a JSON object".to_owned(),
        })?;
    let obj = parsed.as_object().ok_or_else(|| Error::InvalidFieldValue {
        field: "address".to_owned(),
        reason: "must be a JSON object".to_owned(),
    })?;
    for key in ["street", "city", "postal_code", "country"] {
        if !obj.contains_key(key) {
            return Err(Error::InvalidFieldValue {
                field: "address".to_owned(),
                reason: format!("missing required key '{key}'"),
            });
        }
    }
    let country = obj["country"]
        .as_str()
        .ok_or_else(|| Error::InvalidFieldValue {
            field: "address".to_owned(),
            reason: "'country' must be a string".to_owned(),
        })?;
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(Error::InvalidFieldValue {
            field: "address".to_owned(),
            reason: "'country' must be exactly 2 uppercase ASCII letters".to_owned(),
        });
    }
    if !ISO_3166_1_ALPHA2.contains(&country) {
        return Err(Error::InvalidFieldValue {
            field: "address".to_owned(),
            reason: format!("'{country}' is not a recognised ISO 3166-1 alpha-2 country code"),
        });
    }
    Ok(())
}

fn validate_company_name(value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidFieldValue {
            field: "company_name".to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > 256 {
        return Err(Error::InvalidFieldValue {
            field: "company_name".to_owned(),
            reason: format!("must not exceed 256 bytes, got {}", value.len()),
        });
    }
    Ok(())
}

fn validate_eu_vat_number(value: &str) -> crate::Result<()> {
    let bad = || Error::InvalidFieldValue {
        field: "eu_vat_number".to_owned(),
        reason: format!("'{value}' is not a valid EU VAT number (CC + 2–13 alphanumeric chars)"),
    };
    if value.len() < 4 {
        return Err(bad());
    }
    let (prefix, suffix) = value.split_at(2);
    if !prefix.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(bad());
    }
    if !EU_MEMBER_STATE_CODES.contains(&prefix) {
        return Err(Error::InvalidFieldValue {
            field: "eu_vat_number".to_owned(),
            reason: format!("'{prefix}' is not an EU member state code"),
        });
    }
    if suffix.len() < 2 || suffix.len() > 13 {
        return Err(bad());
    }
    if !suffix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'*')
    {
        return Err(bad());
    }
    Ok(())
}

fn validate_chamber_of_commerce(value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidFieldValue {
            field: "chamber_of_commerce".to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > 64 {
        return Err(Error::InvalidFieldValue {
            field: "chamber_of_commerce".to_owned(),
            reason: format!("must not exceed 64 bytes, got {}", value.len()),
        });
    }
    Ok(())
}

fn validate_date_of_birth(value: &str) -> crate::Result<()> {
    let err = |reason: &str| Error::InvalidFieldValue {
        field: "date_of_birth".to_owned(),
        reason: reason.to_owned(),
    };
    // Expect YYYY-MM-DD
    let mut parts = value.splitn(4, '-');
    let year_str = parts
        .next()
        .ok_or_else(|| err("must be in YYYY-MM-DD format"))?;
    let month_str = parts
        .next()
        .ok_or_else(|| err("must be in YYYY-MM-DD format"))?;
    let day_str = parts
        .next()
        .ok_or_else(|| err("must be in YYYY-MM-DD format"))?;
    if parts.next().is_some() {
        return Err(err("must be in YYYY-MM-DD format"));
    }
    let year: u32 = year_str
        .parse()
        .map_err(|_| err("year must be a 4-digit number"))?;
    let month: u32 = month_str
        .parse()
        .map_err(|_| err("month must be a number"))?;
    let day: u32 = day_str.parse().map_err(|_| err("day must be a number"))?;
    if !(1..=12).contains(&month) {
        return Err(err("month must be 1–12"));
    }
    if !(1..=31).contains(&day) {
        return Err(err("day must be 1–31"));
    }
    let age = current_year().saturating_sub(year);
    if age < 13 {
        return Err(err("date of birth implies age under 13 years"));
    }
    Ok(())
}

fn validate_national_id(value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidFieldValue {
            field: "national_id".to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > 128 {
        return Err(Error::InvalidFieldValue {
            field: "national_id".to_owned(),
            reason: format!("must not exceed 128 bytes, got {}", value.len()),
        });
    }
    Ok(())
}

fn validate_nationality(value: &str) -> crate::Result<()> {
    if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(Error::InvalidFieldValue {
            field: "nationality".to_owned(),
            reason: "must be exactly 2 uppercase ASCII letters (ISO 3166-1 alpha-2)".to_owned(),
        });
    }
    if !ISO_3166_1_ALPHA2.contains(&value) {
        return Err(Error::InvalidFieldValue {
            field: "nationality".to_owned(),
            reason: format!("'{value}' is not a recognised ISO 3166-1 alpha-2 country code"),
        });
    }
    Ok(())
}

fn validate_industry(value: &str) -> crate::Result<()> {
    const VALID: &[&str] = &["Academic", "Commercial", "Government", "NGO", "Personal"];
    if !VALID.contains(&value) {
        return Err(Error::InvalidFieldValue {
            field: "industry".to_owned(),
            reason: format!(
                "'{value}' is not valid; accepted values: {}",
                VALID.join(", ")
            ),
        });
    }
    Ok(())
}

fn validate_student_id(value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidFieldValue {
            field: "student_id".to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    if value.len() > 64 {
        return Err(Error::InvalidFieldValue {
            field: "student_id".to_owned(),
            reason: format!("must not exceed 64 bytes, got {}", value.len()),
        });
    }
    Ok(())
}

fn version_matches(pattern: &str, actual: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pp: Vec<&str> = pattern.split('.').collect();
    let ap: Vec<&str> = actual.split('.').collect();
    if pp.len() != 3 || ap.len() != 3 {
        return false;
    }
    pp.iter().zip(ap.iter()).all(|(p, a)| *p == "x" || p == a)
}

fn specificity_score(pattern: &str) -> u8 {
    if pattern == "*" {
        return 0;
    }
    // At most 3 non-wildcard segments in a 3-part pattern , safe to unwrap
    u8::try_from(pattern.split('.').filter(|seg| *seg != "x").count()).unwrap_or(3)
}

//   Public API

/// Convert stored term-declaration rows into a validated `TermDeclarations` value.
///
/// Requires both the declaration row **and** the parent product because
/// `connectivity` and `transfer` live on `Product`, not `ProductTermDeclaration`.
pub fn term_declarations_from_storage(
    decl: &ProductTermDeclaration,
    product: &Product,
) -> crate::Result<TermDeclarations> {
    let warranty = decl.warranty.parse::<WarrantyDeclaration>().map_err(|_| {
        Error::InvalidTermDeclarationValue {
            field: "warranty",
            value: decl.warranty.clone(),
        }
    })?;
    let refund = decl.refund.parse::<RefundDeclaration>().map_err(|_| {
        Error::InvalidTermDeclarationValue {
            field: "refund",
            value: decl.refund.clone(),
        }
    })?;
    let revocation = decl
        .revocation
        .parse::<RevocationDeclaration>()
        .map_err(|_| Error::InvalidTermDeclarationValue {
            field: "revocation",
            value: decl.revocation.clone(),
        })?;
    let expiry = decl.expiry.parse::<ExpiryDeclaration>().map_err(|_| {
        Error::InvalidTermDeclarationValue {
            field: "expiry",
            value: decl.expiry.clone(),
        }
    })?;
    let support_scope = decl
        .support_scope
        .as_deref()
        .map(|s| {
            s.parse::<SupportScope>()
                .map_err(|_| Error::InvalidTermDeclarationValue {
                    field: "support_scope",
                    value: s.to_owned(),
                })
        })
        .transpose()?;
    let updates_policy = decl.updates_policy.parse::<UpdatesPolicy>().map_err(|_| {
        Error::InvalidTermDeclarationValue {
            field: "updates_policy",
            value: decl.updates_policy.clone(),
        }
    })?;
    Ok(TermDeclarations::new(
        warranty,
        refund,
        revocation,
        expiry,
        decl.support_available,
        support_scope,
        updates_policy,
        connectivity_from_mode(product.connectivity_mode),
        transfer_from_policy(product.transfer_policy),
    ))
}

/// Validate all string enum fields in a `ProductTermDeclaration` without a product context.
pub fn validate_term_declaration(decl: &ProductTermDeclaration) -> crate::Result<()> {
    decl.warranty.parse::<WarrantyDeclaration>().map_err(|_| {
        Error::InvalidTermDeclarationValue {
            field: "warranty",
            value: decl.warranty.clone(),
        }
    })?;
    decl.refund
        .parse::<RefundDeclaration>()
        .map_err(|_| Error::InvalidTermDeclarationValue {
            field: "refund",
            value: decl.refund.clone(),
        })?;
    decl.revocation
        .parse::<RevocationDeclaration>()
        .map_err(|_| Error::InvalidTermDeclarationValue {
            field: "revocation",
            value: decl.revocation.clone(),
        })?;
    decl.expiry
        .parse::<ExpiryDeclaration>()
        .map_err(|_| Error::InvalidTermDeclarationValue {
            field: "expiry",
            value: decl.expiry.clone(),
        })?;
    if let Some(s) = &decl.support_scope {
        s.parse::<SupportScope>()
            .map_err(|_| Error::InvalidTermDeclarationValue {
                field: "support_scope",
                value: s.clone(),
            })?;
    }
    decl.updates_policy.parse::<UpdatesPolicy>().map_err(|_| {
        Error::InvalidTermDeclarationValue {
            field: "updates_policy",
            value: decl.updates_policy.clone(),
        }
    })?;
    Ok(())
}

/// Generate a Typst source template pre-filled with the product's term declarations.
pub async fn generate_terms_template<S: VendorStore>(
    store: &S,
    product_id: Uuid,
) -> crate::Result<String> {
    let product = store
        .get_product(product_id)
        .await?
        .ok_or(Error::NotFound)?;
    let decl = store
        .get_term_declaration(product_id)
        .await?
        .ok_or(Error::TermDeclarationsMissing)?;
    let term_decls = term_declarations_from_storage(&decl, &product)?;
    Ok(generate_template(&term_decls))
}

/// Upload a new terms document, validate it against the stored declarations, and persist it.
pub async fn upload_terms_document<S: VendorStore>(
    store: &S,
    product_id: Uuid,
    typst_source: String,
    now_ns: i64,
) -> crate::Result<(Uuid, TermsValidationReport)> {
    let product = store
        .get_product(product_id)
        .await?
        .ok_or(Error::NotFound)?;
    let decl = store
        .get_term_declaration(product_id)
        .await?
        .ok_or(Error::TermDeclarationsMissing)?;
    let term_decls = term_declarations_from_storage(&decl, &product)?;
    let report = validate_terms(&term_decls, &typst_source);
    let rendered_hash = blake3::hash(typst_source.as_bytes()).to_string();
    let findings_json =
        serde_json::to_string(&report.findings).map_err(|e| Error::Corrupt(e.to_string()))?;
    let storage_status = map_validation_status(report.status);
    let doc = ProductTermsDocument {
        id: Uuid::new_v4(),
        product_id,
        typst_source,
        rendered_hash,
        validation_status: storage_status,
        validation_findings: findings_json,
        vendor_acknowledged_at: None,
        vendor_acknowledged_findings: None,
        activated_at: None,
        created_at: now_ns,
    };
    store.create_terms_document(&doc).await?;
    Ok((doc.id, report))
}

/// Record vendor acknowledgment of warnings on a terms document.
pub async fn acknowledge_terms_warnings<S: VendorStore>(
    store: &S,
    doc_id: Uuid,
    now_ns: i64,
) -> crate::Result<()> {
    let doc = store
        .get_terms_document(doc_id)
        .await?
        .ok_or(Error::NotFound)?;
    if doc.validation_status != TermsValidationStatus::Warnings {
        return Err(Error::InvalidTransition(
            "acknowledge is only valid for documents with Warnings status".into(),
        ));
    }
    store
        .acknowledge_terms_findings(doc_id, now_ns, &doc.validation_findings)
        .await
}

/// Activate a terms document, enforcing lifecycle constraints.
///
/// Conflicts block activation unconditionally; Warnings require prior acknowledgment.
pub async fn activate_terms_document<S: VendorStore>(
    store: &S,
    doc_id: Uuid,
    now_ns: i64,
) -> crate::Result<()> {
    let doc = store
        .get_terms_document(doc_id)
        .await?
        .ok_or(Error::NotFound)?;
    match doc.validation_status {
        TermsValidationStatus::Conflicts => return Err(Error::TermsConflictsUnresolved),
        TermsValidationStatus::Warnings => {
            if doc.vendor_acknowledged_at.is_none() {
                return Err(Error::TermsWarningsUnacknowledged);
            }
        }
        TermsValidationStatus::Valid | TermsValidationStatus::PendingReview => {}
    }
    store.activate_terms_document(doc_id, now_ns).await
}

/// Gate check run before a product is marked active for enrollment.
///
/// In order this verifies:
/// 1. Term declarations exist and parse cleanly.
/// 2. At least one terms document is ready (Valid, or Warnings with acknowledgment).
/// 3. Customer field configuration passes GDPR rule validation.
/// 4. At least one terms document has been formally activated.
pub async fn check_activation_gate<S: VendorStore>(
    store: &S,
    product_id: Uuid,
) -> crate::Result<()> {
    let product = store
        .get_product(product_id)
        .await?
        .ok_or(Error::NotFound)?;
    let decl = store
        .get_term_declaration(product_id)
        .await?
        .ok_or(Error::TermDeclarationsMissing)?;
    term_declarations_from_storage(&decl, &product)?;

    let docs = store.list_terms_documents(product_id).await?;
    let has_ready_doc = docs.iter().any(|d| match d.validation_status {
        TermsValidationStatus::Valid => true,
        TermsValidationStatus::Warnings => d.vendor_acknowledged_at.is_some(),
        _ => false,
    });
    if !has_ready_doc {
        return Err(Error::TermsDocumentNotReady);
    }

    let fields = store.get_customer_fields(product_id).await?;
    validate_customer_fields(&fields).map_err(|_| Error::CustomerFieldsInvalid)?;

    let has_activated = docs.iter().any(|d| d.activated_at.is_some());
    if !has_activated {
        return Err(Error::TermsDocumentNotActivated);
    }

    Ok(())
}

/// Validate GDPR rules for a product's customer field configuration.
///
/// Does not persist anything; call before `replace_customer_fields`.
pub fn validate_customer_fields(fields: &[ProductCustomerField]) -> crate::Result<()> {
    for field in fields {
        if !KNOWN_FIELD_KEYS.contains(&field.field_key.as_str()) {
            return Err(Error::UnknownFieldKey(field.field_key.clone()));
        }
        if field.field_key == "national_id" && field.gdpr_basis != GdprBasis::LegalObligation {
            return Err(Error::NationalIdRequiresLegalObligation);
        }
        if field.gdpr_basis == GdprBasis::LegitimateInterest {
            let missing = field
                .purpose_description
                .as_deref()
                .is_none_or(|s| s.trim().is_empty());
            if missing {
                return Err(Error::LegitimateInterestRequiresPurpose);
            }
        }
    }
    Ok(())
}

/// Validate a single customer-supplied field value against per-key rules.
pub fn validate_field_value(field_key: &str, value: &str) -> crate::Result<()> {
    match field_key {
        "phone" => validate_phone(value),
        "address" => validate_address(value),
        "company_name" => validate_company_name(value),
        "eu_vat_number" => validate_eu_vat_number(value),
        "chamber_of_commerce" => validate_chamber_of_commerce(value),
        "date_of_birth" => validate_date_of_birth(value),
        "national_id" => validate_national_id(value),
        "nationality" => validate_nationality(value),
        "industry" => validate_industry(value),
        "student_id" => validate_student_id(value),
        _ => Err(Error::UnknownFieldKey(field_key.to_owned())),
    }
}

/// Find the most-specific matching upgrade policy for a given version transition.
///
/// Specificity is scored by the number of non-wildcard segments in `from_version`.
/// Ties are broken by `created_at` ascending (earliest policy wins).
pub fn find_best_policy<'a>(
    policies: &'a [UpgradePolicyRow],
    actual_from: &str,
    actual_to: &str,
) -> Option<&'a UpgradePolicyRow> {
    let mut best: Option<(u8, i64, &UpgradePolicyRow)> = None;
    for p in policies {
        if version_matches(&p.from_version, actual_from)
            && version_matches(&p.to_version, actual_to)
        {
            let score = specificity_score(&p.from_version);
            let better =
                best.is_none_or(|(s, ts, _)| score > s || (score == s && p.created_at < ts));
            if better {
                best = Some((score, p.created_at, p));
            }
        }
    }
    best.map(|(_, _, p)| p)
}

/// Validate a version pattern used in upgrade policy `from_version`.
///
/// Accepts `"*"` (match all), `"1.x.x"` (partial wildcard), or `"1.2.3"` (exact).
pub fn validate_version_pattern(s: &str) -> crate::Result<()> {
    if s == "*" {
        return Ok(());
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidVersionPattern(s.to_owned()));
    }
    for part in parts {
        if part != "x" && part.parse::<u64>().is_err() {
            return Err(Error::InvalidVersionPattern(s.to_owned()));
        }
    }
    Ok(())
}

/// Validate that `s` is a valid `SemVer` version (used for `to_version` where wildcards are banned).
pub fn validate_exact_version(s: &str) -> crate::Result<()> {
    semver::Version::parse(s)
        .map(|_| ())
        .map_err(|_| Error::InvalidVersionPattern(s.to_owned()))
}

/// Create and persist an upgrade policy after validating version strings.
pub async fn create_upgrade_policy<S: VendorStore>(
    store: &S,
    product_id: Uuid,
    from_version: &str,
    to_version: &str,
    policy: UpgradePolicy,
    now_ns: i64,
) -> crate::Result<Uuid> {
    validate_version_pattern(from_version)?;
    validate_exact_version(to_version)?;
    let row = UpgradePolicyRow {
        id: Uuid::new_v4(),
        product_id,
        from_version: from_version.to_owned(),
        to_version: to_version.to_owned(),
        policy,
        created_at: now_ns,
    };
    store.create_upgrade_policy(&row).await?;
    Ok(row.id)
}

/// Retrieve a single upgrade policy by ID.
pub async fn get_upgrade_policy<S: VendorStore>(
    store: &S,
    id: Uuid,
) -> crate::Result<Option<UpgradePolicyRow>> {
    store.get_upgrade_policy(id).await
}

/// List all upgrade policies for a product.
pub async fn list_upgrade_policies<S: VendorStore>(
    store: &S,
    product_id: Uuid,
) -> crate::Result<Vec<UpgradePolicyRow>> {
    store.list_upgrade_policies(product_id).await
}

/// Delete an upgrade policy by ID.
pub async fn delete_upgrade_policy<S: VendorStore>(store: &S, id: Uuid) -> crate::Result<()> {
    store.delete_upgrade_policy(id).await
}
