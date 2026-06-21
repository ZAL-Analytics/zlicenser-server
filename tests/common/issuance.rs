#![allow(dead_code)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

use zlicenser_server::{
    issuance::{
        handlers::{
            ConsentInput, HandlerContext, LicenseOffer, LicenseReceipt, LicenseRequest,
            ServerConfig, handle_license_receipt, handle_license_request,
        },
        revoke, transfer,
        tsa::TsaProvider,
        upgrade,
    },
    payment::{
        CaptureConfirmation, IntentStatus, Money, PaymentIntent, PaymentMetadata, PaymentProvider,
        PaymentTier,
    },
    storage::{
        Storage,
        types::{LicenseStatus, RevocationSource, TransferStatus, UpgradePolicy, UpgradePolicyRow},
    },
};

use super::{make_customer, make_license, make_product, make_seat_binding, make_terms_doc, uid};

struct OkPayment;

#[async_trait::async_trait]
impl PaymentProvider for OkPayment {
    fn tier(&self) -> PaymentTier {
        PaymentTier::Verified
    }
    fn is_payment_sandbox(&self) -> bool {
        false
    }
    async fn create_intent(
        &self,
        _money: Money,
        _meta: PaymentMetadata,
    ) -> zlicenser_server::Result<PaymentIntent> {
        Ok(PaymentIntent {
            intent_id: "pi_ok".into(),
            client_secret: "cs_ok".into(),
        })
    }
    async fn get_intent_status(&self, _id: &str) -> zlicenser_server::Result<IntentStatus> {
        Ok(IntentStatus::RequiresCapture)
    }
    async fn capture_intent(&self, _id: &str) -> zlicenser_server::Result<CaptureConfirmation> {
        Ok(CaptureConfirmation {
            transaction_id: "txn_ok".into(),
            captured_at_ns: 1_000_000_000,
        })
    }
    async fn cancel_intent(&self, _id: &str) -> zlicenser_server::Result<()> {
        Ok(())
    }
}

struct FailedPayment;

#[async_trait::async_trait]
impl PaymentProvider for FailedPayment {
    fn tier(&self) -> PaymentTier {
        PaymentTier::Verified
    }
    fn is_payment_sandbox(&self) -> bool {
        false
    }
    async fn create_intent(
        &self,
        _money: Money,
        _meta: PaymentMetadata,
    ) -> zlicenser_server::Result<PaymentIntent> {
        Ok(PaymentIntent {
            intent_id: "pi_fail".into(),
            client_secret: "cs_fail".into(),
        })
    }
    async fn get_intent_status(&self, _id: &str) -> zlicenser_server::Result<IntentStatus> {
        Ok(IntentStatus::Failed)
    }
    async fn capture_intent(&self, _id: &str) -> zlicenser_server::Result<CaptureConfirmation> {
        panic!("capture_intent should not be called on FailedPayment")
    }
    async fn cancel_intent(&self, _id: &str) -> zlicenser_server::Result<()> {
        Ok(())
    }
}

struct OkTsa;

#[async_trait::async_trait]
impl TsaProvider for OkTsa {
    async fn timestamp(&self, _digest: &[u8; 32]) -> zlicenser_server::Result<Vec<u8>> {
        Ok(vec![0xabu8; 64])
    }
}

struct FailTsa;

#[async_trait::async_trait]
impl TsaProvider for FailTsa {
    async fn timestamp(&self, _digest: &[u8; 32]) -> zlicenser_server::Result<Vec<u8>> {
        Err(zlicenser_server::Error::TsaFailed(
            "simulated failure".into(),
        ))
    }
}

pub async fn setup_product<S: Storage>(storage: &S) -> Uuid {
    let product_id = uid();
    storage
        .create_product(&make_product(product_id))
        .await
        .unwrap();
    let doc_id = uid();
    storage
        .create_terms_document(&make_terms_doc(doc_id, product_id))
        .await
        .unwrap();
    storage
        .activate_terms_document(doc_id, 1_000_000)
        .await
        .unwrap();
    product_id
}

fn make_ctx<S: Storage>(
    storage: Arc<S>,
    payment: impl PaymentProvider + 'static,
    tsa: impl TsaProvider + 'static,
    offer_ttl_ns: Option<i64>,
) -> Arc<HandlerContext<S>> {
    Arc::new(HandlerContext {
        storage,
        payment: Arc::new(payment),
        tsa: Arc::new(tsa),
        signing_key: Arc::new(SigningKey::generate(&mut rand::thread_rng())),
        at_rest_key: Arc::new([0u8; 32]),
        config: Arc::new(ServerConfig {
            offer_ttl_ns,
            stripe_webhook_secret: None,
            api_bearer_token: None,
        }),
        email: None,
    })
}

async fn do_request<S: Storage>(
    ctx: &HandlerContext<S>,
    product_id: Uuid,
    fp: Vec<u8>,
) -> (LicenseOffer, SigningKey) {
    let customer_sk = SigningKey::generate(&mut rand::thread_rng());
    let customer_pk = customer_sk.verifying_key();
    let req = LicenseRequest {
        product_id,
        protocol_version: 1,
        client_version: "1.0.0".to_string(),
        fingerprint_commitment: fp,
        customer_pubkey: customer_pk.to_bytes(),
        identity_name: "Test User".to_string(),
        identity_email: "test@example.com".to_string(),
        identity_field_values: "{}".to_string(),
    };
    let offer = handle_license_request(ctx, req).await.unwrap();
    (offer, customer_sk)
}

fn sign_receipt(offer: &LicenseOffer, customer_sk: &SigningKey) -> LicenseReceipt {
    let sig = customer_sk.sign(&offer.offer_nonce);
    LicenseReceipt {
        offer_nonce: offer.offer_nonce.clone(),
        customer_signature: sig.to_bytes(),
        consent: ConsentInput {
            checkboxes_ticked: vec!["agree".to_string()],
            accepted_at_ns: 1_000_000_000,
            ip_address: "127.0.0.1".to_string(),
        },
    }
}

pub async fn test_enroll_happy_path<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), OkPayment, OkTsa, None);

    let (offer, customer_sk) = do_request(&ctx, product_id, vec![0xabu8; 32]).await;
    let receipt = sign_receipt(&offer, &customer_sk);
    let grant = handle_license_receipt(&ctx, offer.session_id, receipt)
        .await
        .unwrap();

    let session = storage
        .get_enrollment_session(offer.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        session.state,
        zlicenser_server::storage::types::EnrollmentState::Issued
    );
    assert_eq!(session.license_id, Some(grant.license_id));

    let license = storage
        .get_license(grant.license_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(license.status, LicenseStatus::Active);
    assert_eq!(license.product_id, product_id);

    let bindings = storage.list_seat_bindings(grant.license_id).await.unwrap();
    assert_eq!(bindings.len(), 1);

    let secret = storage.get_issuance_secret(grant.license_id).await.unwrap();
    assert!(secret.is_some());

    let txn = storage
        .get_payment_transaction_for_license(grant.license_id)
        .await
        .unwrap();
    assert!(txn.is_some());

    let consents = storage
        .get_consent_records_for_license(grant.license_id)
        .await
        .unwrap();
    assert_eq!(consents.len(), 1);
}

pub async fn test_enroll_idempotent<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), OkPayment, OkTsa, None);

    let (offer, customer_sk) = do_request(&ctx, product_id, vec![0xcdu8; 32]).await;
    let receipt = sign_receipt(&offer, &customer_sk);
    let grant1 = handle_license_receipt(&ctx, offer.session_id, receipt)
        .await
        .unwrap();

    let dummy = LicenseReceipt {
        offer_nonce: vec![0u8; 32],
        customer_signature: [0u8; 64],
        consent: ConsentInput {
            checkboxes_ticked: vec!["again".to_string()],
            accepted_at_ns: 1,
            ip_address: "1.2.3.4".to_string(),
        },
    };
    let grant2 = handle_license_receipt(&ctx, offer.session_id, dummy)
        .await
        .unwrap();

    assert_eq!(grant1.license_id, grant2.license_id);

    let bindings = storage.list_seat_bindings(grant1.license_id).await.unwrap();
    assert_eq!(bindings.len(), 1);
    let consents = storage
        .get_consent_records_for_license(grant1.license_id)
        .await
        .unwrap();
    assert_eq!(consents.len(), 1);
}

pub async fn test_enroll_offer_expired<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), OkPayment, OkTsa, Some(-1_000_000_000_000));

    let (offer, customer_sk) = do_request(&ctx, product_id, vec![0xefu8; 32]).await;
    let receipt = sign_receipt(&offer, &customer_sk);
    let err = handle_license_receipt(&ctx, offer.session_id, receipt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, zlicenser_server::Error::OfferExpired));
}

pub async fn test_enroll_nonce_mismatch<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), OkPayment, OkTsa, None);

    let (offer, customer_sk) = do_request(&ctx, product_id, vec![0x11u8; 32]).await;
    let wrong_nonce = vec![0xffu8; 32];
    let sig = customer_sk.sign(&wrong_nonce);
    let bad_receipt = LicenseReceipt {
        offer_nonce: wrong_nonce,
        customer_signature: sig.to_bytes(),
        consent: ConsentInput {
            checkboxes_ticked: vec!["agree".to_string()],
            accepted_at_ns: 1_000_000_000,
            ip_address: "127.0.0.1".to_string(),
        },
    };

    let err = handle_license_receipt(&ctx, offer.session_id, bad_receipt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, zlicenser_server::Error::OfferNonceMismatch));
}

pub async fn test_enroll_bad_signature<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), OkPayment, OkTsa, None);

    let (offer, _customer_sk) = do_request(&ctx, product_id, vec![0x22u8; 32]).await;
    let bad_receipt = LicenseReceipt {
        offer_nonce: offer.offer_nonce.clone(),
        customer_signature: [0u8; 64],
        consent: ConsentInput {
            checkboxes_ticked: vec!["agree".to_string()],
            accepted_at_ns: 1_000_000_000,
            ip_address: "127.0.0.1".to_string(),
        },
    };

    let err = handle_license_receipt(&ctx, offer.session_id, bad_receipt)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        zlicenser_server::Error::InvalidReceiptSignature
    ));
}

pub async fn test_enroll_payment_not_held<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), FailedPayment, OkTsa, None);

    let (offer, customer_sk) = do_request(&ctx, product_id, vec![0x33u8; 32]).await;
    let receipt = sign_receipt(&offer, &customer_sk);
    let err = handle_license_receipt(&ctx, offer.session_id, receipt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, zlicenser_server::Error::PaymentNotHeld));
}

pub async fn test_enroll_tsa_failure<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let ctx = make_ctx(storage.clone(), OkPayment, FailTsa, None);

    let (offer, customer_sk) = do_request(&ctx, product_id, vec![0x44u8; 32]).await;
    let receipt = sign_receipt(&offer, &customer_sk);
    let err = handle_license_receipt(&ctx, offer.session_id, receipt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, zlicenser_server::Error::TsaFailed(_)));
}

pub async fn test_revoke_license<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let cust_id = uid();
    storage
        .create_customer(&make_customer(cust_id, product_id))
        .await
        .unwrap();
    let lic_id = uid();
    storage
        .create_license(&make_license(lic_id, cust_id, product_id))
        .await
        .unwrap();

    revoke::revoke_license(
        &storage,
        lic_id,
        Some("fraud".to_string()),
        RevocationSource::Api,
    )
    .await
    .unwrap();

    let license = storage.get_license(lic_id).await.unwrap().unwrap();
    assert_eq!(license.status, LicenseStatus::Revoked);

    let record = storage
        .get_revocation_record(lic_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.reason.as_deref(), Some("fraud"));

    revoke::revoke_license(&storage, lic_id, None, RevocationSource::Api)
        .await
        .unwrap();

    let record2 = storage
        .get_revocation_record(lic_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record2.reason.as_deref(), Some("fraud"));
}

pub async fn test_transfer_approve<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let cust_id = uid();
    storage
        .create_customer(&make_customer(cust_id, product_id))
        .await
        .unwrap();
    let lic_id = uid();
    storage
        .create_license(&make_license(lic_id, cust_id, product_id))
        .await
        .unwrap();
    let fp_a = vec![0xaau8; 32];
    let fp_b = vec![0xbbu8; 32];
    let binding_id = uid();
    storage
        .create_seat_binding(&make_seat_binding(binding_id, lic_id, fp_a.clone()))
        .await
        .unwrap();

    let tr = transfer::request_transfer(&storage, lic_id, fp_a.clone(), fp_b.clone())
        .await
        .unwrap();
    assert_eq!(tr.status, TransferStatus::Pending);

    transfer::approve_transfer(&storage, tr.id, Some("ok".to_string()))
        .await
        .unwrap();

    let old_binding = storage.get_seat_binding(binding_id).await.unwrap().unwrap();
    assert!(old_binding.revoked_at.is_some());

    let new_binding = storage
        .find_seat_binding_by_commitment(lic_id, &fp_b)
        .await
        .unwrap();
    assert!(new_binding.is_some());

    let resolved = storage.get_transfer_request(tr.id).await.unwrap().unwrap();
    assert_eq!(resolved.status, TransferStatus::Approved);
}

pub async fn test_transfer_reject<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let cust_id = uid();
    storage
        .create_customer(&make_customer(cust_id, product_id))
        .await
        .unwrap();
    let lic_id = uid();
    storage
        .create_license(&make_license(lic_id, cust_id, product_id))
        .await
        .unwrap();
    let fp_a = vec![0xccu8; 32];
    let fp_b = vec![0xddu8; 32];
    let binding_id = uid();
    storage
        .create_seat_binding(&make_seat_binding(binding_id, lic_id, fp_a.clone()))
        .await
        .unwrap();

    let tr = transfer::request_transfer(&storage, lic_id, fp_a.clone(), fp_b.clone())
        .await
        .unwrap();

    transfer::reject_transfer(&storage, tr.id, Some("denied".to_string()))
        .await
        .unwrap();

    let old_binding = storage.get_seat_binding(binding_id).await.unwrap().unwrap();
    assert!(old_binding.revoked_at.is_none());
    assert!(old_binding.transfer_pending_at.is_none());

    let new_binding = storage
        .find_seat_binding_by_commitment(lic_id, &fp_b)
        .await
        .unwrap();
    assert!(new_binding.is_none());

    let resolved = storage.get_transfer_request(tr.id).await.unwrap().unwrap();
    assert_eq!(resolved.status, TransferStatus::Rejected);
}

pub async fn test_upgrade_free<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let cust_id = uid();
    storage
        .create_customer(&make_customer(cust_id, product_id))
        .await
        .unwrap();
    let lic_id = uid();
    storage
        .create_license(&make_license(lic_id, cust_id, product_id))
        .await
        .unwrap();

    let policy = UpgradePolicyRow {
        id: uid(),
        product_id,
        from_version: "1.0.0".to_string(),
        to_version: "2.0.0".to_string(),
        policy: UpgradePolicy::FreeUpgrade,
        created_at: 0,
    };
    storage.create_upgrade_policy(&policy).await.unwrap();

    upgrade::handle_upgrade_activation(&storage, lic_id, "2.0.0")
        .await
        .unwrap();

    let old_lic = storage.get_license(lic_id).await.unwrap().unwrap();
    assert_eq!(old_lic.status, LicenseStatus::Superseded);
    let new_lic_id = old_lic.superseded_by.unwrap();

    let new_lic = storage.get_license(new_lic_id).await.unwrap().unwrap();
    assert_eq!(new_lic.status, LicenseStatus::Active);
    assert_eq!(new_lic.bundle_version, "2.0.0");
    assert_eq!(new_lic.product_id, product_id);
    assert_eq!(new_lic.customer_id, cust_id);
}

pub async fn test_upgrade_same_version_noop<S: Storage + 'static>(storage: Arc<S>) {
    let product_id = setup_product(&*storage).await;
    let cust_id = uid();
    storage
        .create_customer(&make_customer(cust_id, product_id))
        .await
        .unwrap();
    let lic_id = uid();
    storage
        .create_license(&make_license(lic_id, cust_id, product_id))
        .await
        .unwrap();

    upgrade::handle_upgrade_activation(&storage, lic_id, "1.0.0")
        .await
        .unwrap();

    let lic = storage.get_license(lic_id).await.unwrap().unwrap();
    assert_eq!(lic.status, LicenseStatus::Active);
    assert!(lic.superseded_by.is_none());
}
