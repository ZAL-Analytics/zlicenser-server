use std::sync::Arc;

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use uuid::Uuid;

use super::binding_cert::BindingCert;
use super::email::EmailTransport;
use super::secrets::{SIssue, WrappedSecret, encrypt_s_issue_at_rest, wrap_s_issue_for_airgap};
use super::tsa::{TsaProvider, tsa_with_retry};
use crate::payment::{
    CaptureConfirmation, IntentStatus, Money, PaymentMetadata, PaymentProvider as PaymentTrait,
};
use crate::storage::{
    Storage,
    types::{
        ConnectivityMode, ConsentRecord as StorageConsentRecord, Customer, EnrollmentSession,
        EnrollmentSessionUpdate, EnrollmentState, FingerprintSeatBinding, IssuanceSecret, License,
        LicenseStatus, PaymentStatus, PaymentTransaction, Product, ProviderTier, abandon_reason,
    },
};

/// Sentinel value for `expected_updated_at` that disables the optimistic-locking
/// check. Used only for terminal state transitions (Issued, Abandoned) where a
/// concurrent writer racing us to the same terminal state is harmless.
pub(crate) const SKIP_OPTIMISTIC_LOCK: i64 = 0;

pub struct ServerConfig {
    pub offer_ttl_ns: Option<i64>,
    pub stripe_webhook_secret: Option<String>,
    /// Bearer token for the vendor API. Wrapped in `Secret` so it is never
    /// accidentally logged or exposed via `Debug`.
    pub api_bearer_token: Option<secrecy::Secret<String>>,
}

pub struct HandlerContext<S: Storage> {
    pub storage: Arc<S>,
    pub payment: Arc<dyn PaymentTrait>,
    pub tsa: Arc<dyn TsaProvider>,
    pub signing_key: Arc<SigningKey>,
    pub at_rest_key: Arc<[u8; 32]>,
    pub config: Arc<ServerConfig>,
    pub email: Option<Arc<dyn EmailTransport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientVersionStatus {
    Current,
    UpdateAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseRequest {
    pub product_id: Uuid,
    pub protocol_version: u16,
    pub client_version: String,
    pub fingerprint_commitment: Vec<u8>,
    pub customer_pubkey: [u8; 32],
    pub identity_name: String,
    pub identity_email: String,
    pub identity_field_values: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseOffer {
    pub session_id: Uuid,
    pub offer_nonce: Vec<u8>,
    pub expires_at_ns: i64,
    pub payment_client_secret: String,
    pub payment_intent_id: String,
    pub client_version_status: ClientVersionStatus,
    pub terms_document_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentInput {
    pub checkboxes_ticked: Vec<String>,
    pub accepted_at_ns: i64,
    pub ip_address: String,
}

pub struct LicenseReceipt {
    pub offer_nonce: Vec<u8>,
    pub customer_signature: [u8; 64],
    pub consent: ConsentInput,
}

pub struct IssuedGrant {
    pub license_id: Uuid,
    pub binding_cert: BindingCert,
    pub tsa_token: Vec<u8>,
    pub wrapped_secret: Option<WrappedSecret>,
}

#[derive(Serialize, Deserialize)]
struct GrantRecord {
    license_id: Uuid,
    product_id: Uuid,
    fingerprint_commitment: Vec<u8>,
    customer_pubkey: Vec<u8>,
    seat_index: u32,
    issued_at_ns: i64,
    expiry_at_ns: Option<i64>,
    connectivity_mode: String,
    vendor_sig: Vec<u8>,
    tsa_token: Vec<u8>,
    wrapped_ephemeral_pubkey: Option<Vec<u8>>,
    wrapped_ciphertext: Option<Vec<u8>>,
}

#[allow(clippy::too_many_lines)]
pub async fn handle_license_request<S: Storage>(
    ctx: &HandlerContext<S>,
    req: LicenseRequest,
) -> crate::Result<LicenseOffer> {
    let product = ctx
        .storage
        .get_product(req.product_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    if !product.active {
        return Err(crate::Error::ProductInactive);
    }

    let client_ver: semver::Version =
        req.client_version
            .parse()
            .map_err(|_| crate::Error::ClientVersionRejected {
                required: "valid semver".into(),
                got: req.client_version.clone(),
            })?;

    if let Some(required_str) = &product.min_client_version_required {
        let required_ver: semver::Version = required_str.parse().unwrap_or_else(|e| {
            tracing::warn!(raw = %required_str, error = %e, "invalid min_client_version_required in DB, treating as 0.0.0");
            semver::Version::new(0, 0, 0)
        });
        if client_ver < required_ver {
            return Err(crate::Error::ClientVersionRejected {
                required: required_str.clone(),
                got: req.client_version.clone(),
            });
        }
    }

    let client_version_status = if let Some(warn_str) = &product.min_client_version_warning {
        let warn_ver: semver::Version = warn_str.parse().unwrap_or_else(|e| {
            tracing::warn!(raw = %warn_str, error = %e, "invalid min_client_version_warning in DB, treating as 0.0.0");
            semver::Version::new(0, 0, 0)
        });
        if client_ver < warn_ver {
            ClientVersionStatus::UpdateAvailable
        } else {
            ClientVersionStatus::Current
        }
    } else {
        ClientVersionStatus::Current
    };

    let active_bindings = ctx
        .storage
        .count_transferable_seat_bindings(req.product_id)
        .await?;
    if active_bindings
        >= u32::try_from(product.seat_count)
            .map_err(|_| crate::Error::Corrupt("seat_count out of u32 range".into()))?
    {
        return Err(crate::Error::SeatLimitReached);
    }

    let session_id = Uuid::new_v4();

    let intent = ctx
        .payment
        .create_intent(
            Money {
                amount: product.pricing_amount,
                currency: product.pricing_currency.clone(),
            },
            PaymentMetadata {
                product_id: req.product_id,
                session_id,
                customer_email: None,
            },
        )
        .await?;

    let terms_doc = ctx
        .storage
        .get_active_terms_document(req.product_id)
        .await?;
    let terms_document_id = terms_doc.as_ref().map(|d| d.id);

    let mut offer_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut offer_nonce);

    let now = now_ns();
    let offer_ttl = ctx.config.offer_ttl_ns.unwrap_or(30 * 60 * 1_000_000_000);
    let expires_at_ns = now + offer_ttl;

    let offer = LicenseOffer {
        session_id,
        offer_nonce: offer_nonce.to_vec(),
        expires_at_ns,
        payment_client_secret: intent.client_secret.clone(),
        payment_intent_id: intent.intent_id.clone(),
        client_version_status,
        terms_document_id,
    };

    let request_bytes = serialize_request(&req)?;
    let offer_bytes = serialize_offer(&offer)?;

    ctx.storage
        .create_enrollment_session(&EnrollmentSession {
            id: session_id,
            product_id: req.product_id,
            fingerprint_commitment: req.fingerprint_commitment.clone(),
            customer_pubkey: req.customer_pubkey.to_vec(),
            client_version: req.client_version.clone(),
            protocol_version: i64::from(req.protocol_version),
            state: EnrollmentState::OfferPending,
            offer_nonce: Some(offer_nonce.to_vec()),
            offer_expires_at: Some(expires_at_ns),
            terms_document_id,
            request_bytes,
            offer_bytes: Some(offer_bytes),
            receipt_bytes: None,
            payment_intent_id: Some(intent.intent_id.clone()),
            payment_captured: false,
            grant_bytes: None,
            transfer_request_id: None,
            license_id: None,
            abandon_reason: None,
            created_at: now,
            updated_at: now,
        })
        .await?;

    Ok(offer)
}

#[allow(clippy::too_many_lines)]
pub async fn handle_license_receipt<S: Storage + 'static>(
    ctx: &HandlerContext<S>,
    session_id: Uuid,
    receipt: LicenseReceipt,
) -> crate::Result<IssuedGrant> {
    let session = ctx
        .storage
        .get_enrollment_session(session_id)
        .await?
        .ok_or(crate::Error::SessionNotFound)?;

    match session.state {
        EnrollmentState::Issued => {
            let grant_bytes = session.grant_bytes.as_deref().ok_or_else(|| {
                crate::Error::Corrupt("Issued session missing grant_bytes".into())
            })?;
            return deserialize_grant(grant_bytes);
        }
        EnrollmentState::OfferPending => {}
        _ => {
            return Err(crate::Error::InvalidTransition(format!(
                "session is in state {}",
                session.state
            )));
        }
    }

    let now = now_ns();
    if let Some(expires_at) = session.offer_expires_at
        && now > expires_at
    {
        abandon(&ctx.storage, session_id, abandon_reason::OFFER_EXPIRED).await;
        if let Some(intent_id) = &session.payment_intent_id
            && let Err(e) = ctx.payment.cancel_intent(intent_id).await
        {
            tracing::warn!(intent_id = %intent_id, error = %e, "failed to cancel payment intent after offer expiry");
        }
        return Err(crate::Error::OfferExpired);
    }

    let expected_nonce = session
        .offer_nonce
        .as_deref()
        .ok_or_else(|| crate::Error::Corrupt("session missing offer_nonce".into()))?;
    if receipt.offer_nonce != expected_nonce {
        return Err(crate::Error::OfferNonceMismatch);
    }

    let customer_pubkey_bytes: [u8; 32] = session
        .customer_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| crate::Error::Corrupt("customer_pubkey wrong length".into()))?;
    let vk = VerifyingKey::from_bytes(&customer_pubkey_bytes)
        .map_err(|_| crate::Error::InvalidReceiptSignature)?;
    verify_receipt_signature(&receipt, &vk)?;

    validate_consent(&receipt.consent)?;

    let intent_id = session
        .payment_intent_id
        .as_deref()
        .ok_or_else(|| crate::Error::Corrupt("session missing payment_intent_id".into()))?;
    if ctx.payment.get_intent_status(intent_id).await? != IntentStatus::RequiresCapture {
        abandon(&ctx.storage, session_id, abandon_reason::PAYMENT_FAILED).await;
        return Err(crate::Error::PaymentNotHeld);
    }

    let customer = upsert_customer(&ctx.storage, &session).await?;

    let receipt_bytes = serialize_receipt(&receipt)?;

    ctx.storage
        .update_enrollment_session(
            session_id,
            session.updated_at,
            EnrollmentSessionUpdate {
                state: Some(EnrollmentState::ReceiptPending),
                receipt_bytes: Some(receipt_bytes.clone()),
                updated_at: now,
                ..Default::default()
            },
        )
        .await?;

    let offer_bytes = session.offer_bytes.as_deref().unwrap_or_default();
    let tsa_digest: [u8; 32] = sha2::Sha256::new()
        .chain_update(&session.request_bytes)
        .chain_update(offer_bytes)
        .chain_update(&receipt_bytes)
        .finalize()
        .into();

    let tsa_token = match tsa_with_retry(&ctx.tsa, &tsa_digest, 3).await {
        Ok(token) => token,
        Err(e) => {
            let storage_clone = ctx.storage.clone();
            let payment_clone = ctx.payment.clone();
            let intent_id_owned = session.payment_intent_id.clone();
            tokio::spawn(async move {
                if let Some(id) = intent_id_owned
                    && let Err(e) = payment_clone.cancel_intent(&id).await
                {
                    tracing::warn!(intent_id = %id, error = %e, "failed to cancel payment intent after TSA failure");
                }
                abandon(&storage_clone, session_id, abandon_reason::TSA_FAILED).await;
            });
            return Err(crate::Error::TsaFailed(e.to_string()));
        }
    };

    let product = ctx
        .storage
        .get_product(session.product_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    let s_issue = SIssue::generate();
    let seat_index: i64 = 0;
    let license_id = Uuid::new_v4();
    let issued_at_ns = now_ns();
    let expiry_at_ns = compute_expiry(&product, issued_at_ns);

    let mut binding_cert = BindingCert {
        license_id,
        product_id: session.product_id,
        fingerprint_commitment: session
            .fingerprint_commitment
            .as_slice()
            .try_into()
            .map_err(|_| crate::Error::Corrupt("fingerprint_commitment wrong length".into()))?,
        customer_pubkey: customer_pubkey_bytes,
        seat_index: u32::try_from(seat_index)
            .map_err(|_| crate::Error::Corrupt("seat_index out of u32 range".into()))?,
        issued_at_ns,
        expiry_at_ns,
        connectivity_mode: product.connectivity_mode,
        vendor_sig: [0u8; 64],
    };
    binding_cert.sign(&ctx.signing_key);

    let grant = match product.connectivity_mode {
        ConnectivityMode::AirGapped => {
            let wrapped = wrap_s_issue_for_airgap(&s_issue, &customer_pubkey_bytes)?;
            IssuedGrant {
                license_id,
                binding_cert: binding_cert.clone(),
                tsa_token: tsa_token.clone(),
                wrapped_secret: Some(wrapped),
            }
        }
        ConnectivityMode::Online | ConnectivityMode::AlwaysOnline => IssuedGrant {
            license_id,
            binding_cert: binding_cert.clone(),
            tsa_token: tsa_token.clone(),
            wrapped_secret: None,
        },
    };

    let grant_bytes = serialize_grant(&grant)?;

    ctx.storage
        .update_enrollment_session(
            session_id,
            now,
            EnrollmentSessionUpdate {
                state: Some(EnrollmentState::GrantReady),
                grant_bytes: Some(grant_bytes.clone()),
                updated_at: issued_at_ns,
                ..Default::default()
            },
        )
        .await?;

    let payment_sandbox = ctx.payment.is_payment_sandbox();
    let payment_tier = match ctx.payment.tier() {
        crate::payment::PaymentTier::Verified => ProviderTier::Verified,
        crate::payment::PaymentTier::Pseudonymous => ProviderTier::Pseudonymous,
        crate::payment::PaymentTier::Anonymous => ProviderTier::Anonymous,
    };

    let intent_id_str = session
        .payment_intent_id
        .as_deref()
        .unwrap_or_default()
        .to_owned();

    let confirmation = match ctx.payment.capture_intent(&intent_id_str).await {
        Ok(c) => c,
        Err(e) => {
            let storage_clone = ctx.storage.clone();
            let payment_clone = ctx.payment.clone();
            tokio::spawn(async move {
                if let Err(e) = payment_clone.cancel_intent(&intent_id_str).await {
                    tracing::warn!(intent_id = %intent_id_str, error = %e, "failed to cancel payment intent after capture failure");
                }
                abandon(&storage_clone, session_id, abandon_reason::CAPTURE_FAILED).await;
            });
            return Err(crate::Error::PaymentCaptureFailed(e.to_string()));
        }
    };

    issue_all_records(
        &ctx.storage,
        &ctx.at_rest_key,
        IssueParams {
            session: &session,
            product: &product,
            customer: &customer,
            receipt: Some(&receipt),
            confirmation: &confirmation,
            license_id,
            seat_index,
            expiry_at_ns,
            session_id,
            payment_sandbox,
            payment_tier,
            s_issue,
        },
    )
    .await?;

    if let Some(transport) = &ctx.email {
        let t = transport.clone();
        tokio::spawn(async move {
            if let Err(e) = t.send_grant_confirmation(license_id).await {
                tracing::warn!(license_id = %license_id, error = %e, "failed to send grant confirmation email");
            }
        });
    }

    deserialize_grant(&grant_bytes)
}

pub(crate) struct IssueParams<'a> {
    pub session: &'a EnrollmentSession,
    pub product: &'a Product,
    pub customer: &'a Customer,
    pub receipt: Option<&'a LicenseReceipt>,
    pub confirmation: &'a CaptureConfirmation,
    pub license_id: Uuid,
    pub seat_index: i64,
    pub expiry_at_ns: Option<i64>,
    pub session_id: Uuid,
    pub payment_sandbox: bool,
    pub payment_tier: ProviderTier,
    pub s_issue: SIssue,
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn issue_all_records<S: Storage>(
    storage: &Arc<S>,
    at_rest_key: &[u8; 32],
    p: IssueParams<'_>,
) -> crate::Result<()> {
    let IssueParams {
        session,
        product,
        customer,
        receipt,
        confirmation,
        license_id,
        seat_index,
        expiry_at_ns,
        session_id,
        payment_sandbox,
        payment_tier,
        s_issue,
    } = p;
    let now = now_ns();

    storage
        .create_license(&License {
            id: license_id,
            customer_id: customer.id,
            product_id: session.product_id,
            bundle_version: product.bundle_version.clone(),
            connectivity_mode: product.connectivity_mode,
            seat_count: 1,
            expiry_at: expiry_at_ns,
            status: LicenseStatus::Active,
            superseded_by: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
            email_sent_at: None,
        })
        .await?;

    storage
        .create_seat_binding(&FingerprintSeatBinding {
            id: Uuid::new_v4(),
            license_id,
            fingerprint_commitment: session.fingerprint_commitment.clone(),
            seat_index,
            bound_at: now,
            last_verified_at: None,
            revoked_at: None,
            transfer_pending_at: None,
        })
        .await?;

    match product.connectivity_mode {
        ConnectivityMode::Online | ConnectivityMode::AlwaysOnline => {
            let encrypted = encrypt_s_issue_at_rest(&s_issue, at_rest_key)?;
            drop(s_issue);
            storage
                .create_issuance_secret(&IssuanceSecret {
                    license_id,
                    secret: encrypted,
                    created_at: now,
                })
                .await?;
        }
        ConnectivityMode::AirGapped => {
            drop(s_issue);
        }
    }

    storage
        .create_payment_transaction(&PaymentTransaction {
            id: Uuid::new_v4(),
            license_id,
            provider: product.payment_provider,
            provider_transaction_id: confirmation.transaction_id.clone(),
            amount: product.pricing_amount,
            currency: product.pricing_currency.clone(),
            provider_tier: payment_tier,
            payment_sandbox,
            status: PaymentStatus::Confirmed,
            created_at: now,
            confirmed_at: Some(confirmation.captured_at_ns),
        })
        .await?;

    let (terms_rendered_hash, terms_findings_shown) =
        if let Some(doc_id) = session.terms_document_id {
            match storage.get_terms_document(doc_id).await? {
                Some(doc) => (doc.rendered_hash.clone(), doc.validation_findings.clone()),
                None => (String::new(), String::new()),
            }
        } else {
            (String::new(), String::new())
        };

    let terms_document_id = session.terms_document_id.unwrap_or_else(Uuid::nil);

    storage
        .create_consent_record(&StorageConsentRecord {
            id: Uuid::new_v4(),
            customer_id: customer.id,
            license_id,
            terms_document_id,
            terms_rendered_hash,
            checkboxes_ticked: receipt.map_or_else(
                || "recovered".to_owned(),
                |r| r.consent.checkboxes_ticked.join(","),
            ),
            accepted_at_ns: receipt.map_or(1, |r| r.consent.accepted_at_ns),
            ip_address: receipt
                .map_or_else(|| "0.0.0.0".to_owned(), |r| r.consent.ip_address.clone()),
            client_version: session.client_version.clone(),
            protocol_version: session.protocol_version,
            terms_findings_shown,
            payment_provider: product.payment_provider,
            payment_provider_tier: payment_tier,
        })
        .await?;

    storage
        .update_enrollment_session(
            session_id,
            SKIP_OPTIMISTIC_LOCK,
            EnrollmentSessionUpdate {
                state: Some(EnrollmentState::Issued),
                payment_captured: Some(true),
                license_id: Some(Some(license_id)),
                updated_at: now,
                ..Default::default()
            },
        )
        .await?;

    Ok(())
}

pub(crate) async fn abandon<S: Storage>(storage: &Arc<S>, session_id: Uuid, reason: &str) {
    let now = now_ns();
    if let Err(e) = storage
        .update_enrollment_session(
            session_id,
            SKIP_OPTIMISTIC_LOCK,
            EnrollmentSessionUpdate {
                state: Some(EnrollmentState::Abandoned),
                abandon_reason: Some(reason.to_owned()),
                updated_at: now,
                ..Default::default()
            },
        )
        .await
    {
        tracing::warn!(session_id = %session_id, error = %e, "failed to mark session Abandoned");
    }
}

pub(crate) async fn upsert_customer<S: Storage>(
    storage: &Arc<S>,
    session: &EnrollmentSession,
) -> crate::Result<Customer> {
    let req: LicenseRequest = serde_json::from_slice(&session.request_bytes)
        .map_err(|e| crate::Error::Corrupt(format!("bad request_bytes: {e}")))?;

    if let Some(existing) = storage
        .find_customer_by_email(session.product_id, &req.identity_email)
        .await?
    {
        return Ok(existing);
    }

    let now = now_ns();
    let customer = Customer {
        id: Uuid::new_v4(),
        product_id: session.product_id,
        full_name: req.identity_name.clone(),
        email: req.identity_email.clone(),
        field_values: req.identity_field_values.clone(),
        created_at: now,
        updated_at: now,
    };
    storage.create_customer(&customer).await?;
    Ok(customer)
}

fn verify_receipt_signature(receipt: &LicenseReceipt, vk: &VerifyingKey) -> crate::Result<()> {
    let sig = Signature::from_bytes(&receipt.customer_signature);
    vk.verify(&receipt.offer_nonce, &sig)
        .map_err(|_| crate::Error::InvalidReceiptSignature)
}

fn validate_consent(consent: &ConsentInput) -> crate::Result<()> {
    if consent.checkboxes_ticked.is_empty() {
        return Err(crate::Error::ConsentInvalid("no checkboxes ticked".into()));
    }
    if consent.accepted_at_ns == 0 {
        return Err(crate::Error::ConsentInvalid(
            "accepted_at_ns must be non-zero".into(),
        ));
    }
    if consent.ip_address.is_empty() {
        return Err(crate::Error::ConsentInvalid("ip_address is empty".into()));
    }
    Ok(())
}

pub(crate) fn compute_expiry(product: &Product, issued_at_ns: i64) -> Option<i64> {
    let policy = product.expiry_policy.trim();
    if policy.is_empty() || policy == "never" {
        return None;
    }
    if let Some(n_str) = policy.strip_suffix('d')
        && let Ok(n) = n_str.parse::<i64>()
    {
        return Some(issued_at_ns + n * 86_400 * 1_000_000_000);
    }
    if let Some(n_str) = policy.strip_suffix('y')
        && let Ok(n) = n_str.parse::<i64>()
    {
        return Some(issued_at_ns + n * 365 * 86_400 * 1_000_000_000);
    }
    None
}

pub(crate) fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn serialize_request(req: &LicenseRequest) -> crate::Result<Vec<u8>> {
    serde_json::to_vec(req).map_err(|e| crate::Error::Corrupt(format!("serialize_request: {e}")))
}

fn serialize_offer(offer: &LicenseOffer) -> crate::Result<Vec<u8>> {
    serde_json::to_vec(offer).map_err(|e| crate::Error::Corrupt(format!("serialize_offer: {e}")))
}

fn serialize_receipt(receipt: &LicenseReceipt) -> crate::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ReceiptRec<'a> {
        offer_nonce: &'a [u8],
        customer_signature: &'a [u8],
        consent: &'a ConsentInput,
    }
    serde_json::to_vec(&ReceiptRec {
        offer_nonce: &receipt.offer_nonce,
        customer_signature: &receipt.customer_signature,
        consent: &receipt.consent,
    })
    .map_err(|e| crate::Error::Corrupt(format!("serialize_receipt: {e}")))
}

pub(crate) fn serialize_grant(grant: &IssuedGrant) -> crate::Result<Vec<u8>> {
    let rec = GrantRecord {
        license_id: grant.license_id,
        product_id: grant.binding_cert.product_id,
        fingerprint_commitment: grant.binding_cert.fingerprint_commitment.to_vec(),
        customer_pubkey: grant.binding_cert.customer_pubkey.to_vec(),
        seat_index: grant.binding_cert.seat_index,
        issued_at_ns: grant.binding_cert.issued_at_ns,
        expiry_at_ns: grant.binding_cert.expiry_at_ns,
        connectivity_mode: grant.binding_cert.connectivity_mode.to_string(),
        vendor_sig: grant.binding_cert.vendor_sig.to_vec(),
        tsa_token: grant.tsa_token.clone(),
        wrapped_ephemeral_pubkey: grant
            .wrapped_secret
            .as_ref()
            .map(|w| w.ephemeral_pubkey.to_vec()),
        wrapped_ciphertext: grant.wrapped_secret.as_ref().map(|w| w.ciphertext.clone()),
    };
    serde_json::to_vec(&rec).map_err(|e| crate::Error::Corrupt(format!("serialize_grant: {e}")))
}

pub(crate) fn deserialize_grant(bytes: &[u8]) -> crate::Result<IssuedGrant> {
    let rec: GrantRecord = serde_json::from_slice(bytes)
        .map_err(|e| crate::Error::Corrupt(format!("deserialize_grant: {e}")))?;

    let license_id = rec.license_id;
    let product_id = rec.product_id;
    let fingerprint_commitment: [u8; 32] = rec
        .fingerprint_commitment
        .try_into()
        .map_err(|_| crate::Error::Corrupt("bad grant fingerprint_commitment length".into()))?;
    let customer_pubkey: [u8; 32] = rec
        .customer_pubkey
        .try_into()
        .map_err(|_| crate::Error::Corrupt("bad grant customer_pubkey length".into()))?;
    let connectivity_mode: ConnectivityMode = rec.connectivity_mode.parse()?;
    let vendor_sig: [u8; 64] = rec
        .vendor_sig
        .try_into()
        .map_err(|_| crate::Error::Corrupt("bad grant vendor_sig length".into()))?;

    let binding_cert = BindingCert {
        license_id,
        product_id,
        fingerprint_commitment,
        customer_pubkey,
        seat_index: rec.seat_index,
        issued_at_ns: rec.issued_at_ns,
        expiry_at_ns: rec.expiry_at_ns,
        connectivity_mode,
        vendor_sig,
    };

    let wrapped_secret = match (rec.wrapped_ephemeral_pubkey, rec.wrapped_ciphertext) {
        (Some(pk_bytes), Some(ct)) => {
            let ephemeral_pubkey: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| crate::Error::Corrupt("bad wrapped_ephemeral_pubkey length".into()))?;
            Some(WrappedSecret {
                ephemeral_pubkey,
                ciphertext: ct,
            })
        }
        _ => None,
    };

    Ok(IssuedGrant {
        license_id,
        binding_cert,
        tsa_token: rec.tsa_token,
        wrapped_secret,
    })
}

pub(crate) fn deserialize_receipt(bytes: &[u8]) -> crate::Result<LicenseReceipt> {
    #[derive(Deserialize)]
    struct ReceiptRec {
        offer_nonce: Vec<u8>,
        customer_signature: Vec<u8>,
        consent: ConsentInput,
    }
    let rec: ReceiptRec = serde_json::from_slice(bytes)
        .map_err(|e| crate::Error::Corrupt(format!("deserialize_receipt: {e}")))?;
    let customer_signature: [u8; 64] = rec
        .customer_signature
        .try_into()
        .map_err(|_| crate::Error::Corrupt("bad receipt customer_signature length".into()))?;
    Ok(LicenseReceipt {
        offer_nonce: rec.offer_nonce,
        customer_signature,
        consent: rec.consent,
    })
}
