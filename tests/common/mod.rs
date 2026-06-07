#![allow(dead_code)]

use uuid::Uuid;

use zlicenser_server::storage::*;

pub struct Fixture {
    pub prod_id: Uuid,
    pub doc_id: Uuid,
    pub doc2_id: Uuid,
    pub cust_id: Uuid,
    pub lic_id: Uuid,
    pub lic2_id: Uuid,
    pub secret_lic_id: Uuid,
    pub binding_id: Uuid,
}

pub fn uid() -> Uuid {
    Uuid::new_v4()
}

pub fn make_vendor() -> VendorConfig {
    VendorConfig {
        id: 1,
        public_key: vec![1u8; 32],
        public_key_fingerprint: "fp-v1".to_string(),
        registered_at: 1_000_000,
        rotated_from_key: None,
        rotated_at: None,
    }
}

pub fn make_product(id: Uuid) -> Product {
    Product {
        id,
        name: "Test Product".to_string(),
        description: "desc".to_string(),
        connectivity_mode: ConnectivityMode::Online,
        seat_count: 5,
        expiry_policy: "1y".to_string(),
        grace_period_days: Some(7),
        heartbeat_interval_secs: Some(300),
        heartbeat_grace_secs: Some(60),
        shutdown_countdown_secs: Some(600),
        tsa_tier: TsaTier::Standard,
        bundle_version: "1.0.0".to_string(),
        transfer_policy: TransferPolicy::VendorApproval,
        pricing_amount: 9900,
        pricing_currency: "EUR".to_string(),
        payment_provider: PaymentProvider::Stripe,
        min_client_version_warning: None,
        min_client_version_required: None,
        active: true,
        created_at: 1_000_000,
        updated_at: 1_000_000,
    }
}

pub fn make_terms_doc(id: Uuid, product_id: Uuid) -> ProductTermsDocument {
    ProductTermsDocument {
        id,
        product_id,
        typst_source: "#document[] {}".to_string(),
        rendered_hash: "abc123".to_string(),
        validation_status: TermsValidationStatus::Valid,
        validation_findings: "[]".to_string(),
        vendor_acknowledged_at: None,
        vendor_acknowledged_findings: None,
        activated_at: None,
        created_at: 1_000_000,
    }
}

pub fn make_customer(id: Uuid, product_id: Uuid) -> Customer {
    Customer {
        id,
        product_id,
        full_name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        field_values: "{}".to_string(),
        created_at: 1_000_000,
        updated_at: 1_000_000,
    }
}

pub fn make_license(id: Uuid, customer_id: Uuid, product_id: Uuid) -> License {
    License {
        id,
        customer_id,
        product_id,
        bundle_version: "1.0.0".to_string(),
        connectivity_mode: ConnectivityMode::Online,
        seat_count: 1,
        expiry_at: Some(2_000_000),
        status: LicenseStatus::Active,
        superseded_by: None,
        revoked_at: None,
        revocation_reason: None,
        created_at: 1_000_000,
        email_sent_at: None,
    }
}

pub fn make_seat_binding(
    id: Uuid,
    license_id: Uuid,
    commitment: Vec<u8>,
) -> FingerprintSeatBinding {
    FingerprintSeatBinding {
        id,
        license_id,
        fingerprint_commitment: commitment,
        seat_index: 0,
        bound_at: 1_000_000,
        last_verified_at: None,
        revoked_at: None,
        transfer_pending_at: None,
    }
}

pub fn make_enrollment_session(id: Uuid, product_id: Uuid) -> EnrollmentSession {
    EnrollmentSession {
        id,
        product_id,
        fingerprint_commitment: vec![0xde; 32],
        customer_pubkey: vec![0xad; 32],
        client_version: "1.0.0".to_string(),
        protocol_version: 1,
        state: EnrollmentState::OfferPending,
        offer_nonce: None,
        offer_expires_at: None,
        terms_document_id: None,
        request_bytes: vec![0x01; 16],
        offer_bytes: None,
        receipt_bytes: None,
        payment_intent_id: None,
        payment_captured: false,
        grant_bytes: None,
        transfer_request_id: None,
        license_id: None,
        abandon_reason: None,
        created_at: 1_000_000,
        updated_at: 1_000_000,
    }
}

pub fn make_session(id: Uuid, binding_id: Uuid) -> ActiveSession {
    ActiveSession {
        id,
        binding_id,
        ephemeral_pubkey: vec![2u8; 32],
        issued_at: 1_000_000,
        expires_at: 9_000_000,
        last_heartbeat_at: None,
        seq_no: 0,
        status: SessionStatus::Active,
    }
}

pub async fn setup(s: &dyn Storage) -> Fixture {
    let f = Fixture {
        prod_id: uid(),
        doc_id: uid(),
        doc2_id: uid(),
        cust_id: uid(),
        lic_id: uid(),
        lic2_id: uid(),
        secret_lic_id: uid(),
        binding_id: uid(),
    };
    s.create_product(&make_product(f.prod_id)).await.unwrap();
    s.create_terms_document(&make_terms_doc(f.doc_id, f.prod_id))
        .await
        .unwrap();
    s.create_terms_document(&make_terms_doc(f.doc2_id, f.prod_id))
        .await
        .unwrap();
    s.create_customer(&make_customer(f.cust_id, f.prod_id))
        .await
        .unwrap();
    s.create_license(&make_license(f.lic_id, f.cust_id, f.prod_id))
        .await
        .unwrap();
    s.create_license(&make_license(f.lic2_id, f.cust_id, f.prod_id))
        .await
        .unwrap();
    s.create_license(&make_license(f.secret_lic_id, f.cust_id, f.prod_id))
        .await
        .unwrap();
    s.create_seat_binding(&make_seat_binding(f.binding_id, f.lic2_id, vec![0xab; 32]))
        .await
        .unwrap();
    f
}

pub async fn test_vendor_config(s: &dyn Storage, _f: &Fixture) {
    let v = make_vendor();
    s.upsert_vendor_config(&v).await.unwrap();
    let got = s.get_vendor_config().await.unwrap().unwrap();
    assert_eq!(got.public_key_fingerprint, "fp-v1");

    s.rotate_vendor_key(&[9u8; 32], "fp-v2", &v.public_key, 2_000_000)
        .await
        .unwrap();
    let got = s.get_vendor_config().await.unwrap().unwrap();
    assert_eq!(got.public_key_fingerprint, "fp-v2");
    assert_eq!(got.rotated_at, Some(2_000_000));
}

pub async fn test_product(s: &dyn Storage, f: &Fixture) {
    let got = s.get_product(f.prod_id).await.unwrap().unwrap();
    assert_eq!(got.name, "Test Product");
    assert!(got.active);

    let products = s.list_products().await.unwrap();
    assert_eq!(products.len(), 1);

    let mut p2 = make_product(f.prod_id);
    p2.name = "Updated".to_string();
    p2.updated_at = 2_000_000;
    s.update_product(&p2).await.unwrap();
    let got = s.get_product(f.prod_id).await.unwrap().unwrap();
    assert_eq!(got.name, "Updated");
}

pub async fn test_term_declaration(s: &dyn Storage, f: &Fixture) {
    let td = ProductTermDeclaration {
        product_id: f.prod_id,
        warranty: "none".to_string(),
        refund: "no refund".to_string(),
        revocation: "immediate".to_string(),
        expiry: "1 year".to_string(),
        support_available: true,
        support_channels: "email".to_string(),
        response_sla_hours: Some(48),
        support_scope: Some("bugs".to_string()),
        support_coverage: Some("9-5".to_string()),
        updates_policy: "minor updates included".to_string(),
    };
    s.upsert_term_declaration(&td).await.unwrap();
    let got = s.get_term_declaration(f.prod_id).await.unwrap().unwrap();
    assert_eq!(got.warranty, "none");

    let td2 = ProductTermDeclaration {
        warranty: "limited".to_string(),
        ..td
    };
    s.upsert_term_declaration(&td2).await.unwrap();
    let got = s.get_term_declaration(f.prod_id).await.unwrap().unwrap();
    assert_eq!(got.warranty, "limited");
}

pub async fn test_terms_documents(s: &dyn Storage, f: &Fixture) {
    let got = s.get_terms_document(f.doc_id).await.unwrap().unwrap();
    assert_eq!(got.rendered_hash, "abc123");
    assert_eq!(got.activated_at, None);

    s.update_terms_document_validation(f.doc_id, TermsValidationStatus::Warnings, "[\"w1\"]")
        .await
        .unwrap();
    let got = s.get_terms_document(f.doc_id).await.unwrap().unwrap();
    assert_eq!(got.validation_status, TermsValidationStatus::Warnings);
    assert_eq!(got.validation_findings, "[\"w1\"]");

    s.acknowledge_terms_findings(f.doc_id, 1_500_000, "[\"w1\"]")
        .await
        .unwrap();
    let got = s.get_terms_document(f.doc_id).await.unwrap().unwrap();
    assert_eq!(got.vendor_acknowledged_at, Some(1_500_000));

    s.activate_terms_document(f.doc_id, 1_600_000)
        .await
        .unwrap();
    let active = s
        .get_active_terms_document(f.prod_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, f.doc_id);
    assert_eq!(active.activated_at, Some(1_600_000));

    s.activate_terms_document(f.doc2_id, 1_700_000)
        .await
        .unwrap();
    let active = s
        .get_active_terms_document(f.prod_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, f.doc2_id);
    let d1_check = s.get_terms_document(f.doc_id).await.unwrap().unwrap();
    assert_eq!(d1_check.activated_at, None);

    let docs = s.list_terms_documents(f.prod_id).await.unwrap();
    assert_eq!(docs.len(), 2);
}

pub async fn test_customer_fields(s: &dyn Storage, f: &Fixture) {
    let f1 = ProductCustomerField {
        id: uid(),
        product_id: f.prod_id,
        field_key: "company".to_string(),
        required: true,
        gdpr_basis: GdprBasis::Contract,
    };
    let f2 = ProductCustomerField {
        id: uid(),
        product_id: f.prod_id,
        field_key: "vat_number".to_string(),
        required: true,
        gdpr_basis: GdprBasis::Contract,
    };
    s.replace_customer_fields(f.prod_id, &[f1, f2])
        .await
        .unwrap();
    let fields = s.get_customer_fields(f.prod_id).await.unwrap();
    assert_eq!(fields.len(), 2);

    let f3 = ProductCustomerField {
        id: uid(),
        product_id: f.prod_id,
        field_key: "phone".to_string(),
        required: true,
        gdpr_basis: GdprBasis::Contract,
    };
    s.replace_customer_fields(f.prod_id, &[f3]).await.unwrap();
    let fields = s.get_customer_fields(f.prod_id).await.unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].field_key, "phone");
}

pub async fn test_upgrade_policies(s: &dyn Storage, f: &Fixture) {
    let upgrade_id = uid();
    let up = UpgradePolicyRow {
        id: upgrade_id,
        product_id: f.prod_id,
        from_version: "1.0.0".to_string(),
        to_version: "2.0.0".to_string(),
        policy: UpgradePolicy::FreeUpgrade,
    };
    s.create_upgrade_policy(&up).await.unwrap();
    let got = s.get_upgrade_policy(upgrade_id).await.unwrap().unwrap();
    assert_eq!(got.from_version, "1.0.0");

    let found = s
        .find_upgrade_policy(f.prod_id, "1.0.0", "2.0.0")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.policy, UpgradePolicy::FreeUpgrade);

    let ups = s.list_upgrade_policies(f.prod_id).await.unwrap();
    assert_eq!(ups.len(), 1);

    s.delete_upgrade_policy(upgrade_id).await.unwrap();
    assert!(s.get_upgrade_policy(upgrade_id).await.unwrap().is_none());

    let err = s.delete_upgrade_policy(upgrade_id).await.unwrap_err();
    assert!(matches!(err, zlicenser_server::Error::NotFound));
}

pub async fn test_customer(s: &dyn Storage, f: &Fixture) {
    let got = s.get_customer(f.cust_id).await.unwrap().unwrap();
    assert_eq!(got.email, "alice@example.com");

    let found = s
        .find_customer_by_email(f.prod_id, "alice@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, f.cust_id);

    let mut c2 = make_customer(f.cust_id, f.prod_id);
    c2.full_name = "Alice Smith".to_string();
    c2.updated_at = 2_000_000;
    s.update_customer(&c2).await.unwrap();
    let got = s.get_customer(f.cust_id).await.unwrap().unwrap();
    assert_eq!(got.full_name, "Alice Smith");
}

pub async fn test_license(s: &dyn Storage, f: &Fixture) {
    let got = s.get_license(f.lic_id).await.unwrap().unwrap();
    assert_eq!(got.status, LicenseStatus::Active);
    assert_eq!(got.seat_count, 1);

    s.update_license_status(
        f.lic_id,
        LicenseStatus::Superseded,
        None,
        None,
        Some(f.lic2_id),
    )
    .await
    .unwrap();
    let got = s.get_license(f.lic_id).await.unwrap().unwrap();
    assert_eq!(got.status, LicenseStatus::Superseded);
    assert_eq!(got.superseded_by, Some(f.lic2_id));

    s.update_license_email_sent(f.lic2_id, 1_800_000)
        .await
        .unwrap();
    let got = s.get_license(f.lic2_id).await.unwrap().unwrap();
    assert_eq!(got.email_sent_at, Some(1_800_000));

    let licenses = s.list_licenses_for_customer(f.cust_id).await.unwrap();
    assert!(licenses.len() >= 2);
}

pub async fn test_consent_record(s: &dyn Storage, f: &Fixture) {
    let consent_id = uid();
    let cr = ConsentRecord {
        id: consent_id,
        customer_id: f.cust_id,
        license_id: f.lic_id,
        terms_document_id: f.doc_id,
        terms_rendered_hash: "abc123".to_string(),
        checkboxes_ticked: "[\"agree\"]".to_string(),
        accepted_at_ns: 1_000_000_000,
        ip_address: "127.0.0.1".to_string(),
        client_version: "1.0.0".to_string(),
        protocol_version: 1,
        terms_findings_shown: "[]".to_string(),
        payment_provider: PaymentProvider::Stripe,
        payment_provider_tier: ProviderTier::Verified,
    };
    s.create_consent_record(&cr).await.unwrap();
    let got = s.get_consent_record(consent_id).await.unwrap().unwrap();
    assert_eq!(got.ip_address, "127.0.0.1");

    let records = s.get_consent_records_for_license(f.lic_id).await.unwrap();
    assert_eq!(records.len(), 1);
}

pub async fn test_seat_binding(s: &dyn Storage, f: &Fixture) {
    let test_lic_id = uid();
    s.create_license(&make_license(test_lic_id, f.cust_id, f.prod_id))
        .await
        .unwrap();

    let b1_id = uid();
    let commitment = vec![0xcd; 32];
    let b1 = make_seat_binding(b1_id, test_lic_id, commitment.clone());
    s.create_seat_binding(&b1).await.unwrap();
    let got = s.get_seat_binding(b1_id).await.unwrap().unwrap();
    assert_eq!(got.fingerprint_commitment, commitment);

    let found = s
        .find_seat_binding_by_commitment(test_lic_id, &commitment)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, b1_id);

    let bindings = s.list_seat_bindings(test_lic_id).await.unwrap();
    assert_eq!(bindings.len(), 1);

    let count = s.count_active_seat_bindings(test_lic_id).await.unwrap();
    assert_eq!(count, 1);

    s.update_seat_binding_verified(b1_id, 1_900_000)
        .await
        .unwrap();
    let got = s.get_seat_binding(b1_id).await.unwrap().unwrap();
    assert_eq!(got.last_verified_at, Some(1_900_000));

    s.revoke_seat_binding(b1_id, 2_000_000).await.unwrap();
    let count = s.count_active_seat_bindings(test_lic_id).await.unwrap();
    assert_eq!(count, 0);
}

pub async fn test_issuance_secret(s: &dyn Storage, f: &Fixture) {
    let sec = IssuanceSecret {
        license_id: f.secret_lic_id,
        secret: vec![0xff; 64],
        created_at: 1_000_000,
    };
    s.create_issuance_secret(&sec).await.unwrap();
    let got = s
        .get_issuance_secret(f.secret_lic_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.secret, vec![0xff; 64]);

    s.delete_issuance_secret(f.secret_lic_id).await.unwrap();
    assert!(s
        .get_issuance_secret(f.secret_lic_id)
        .await
        .unwrap()
        .is_none());

    let err = s.delete_issuance_secret(f.secret_lic_id).await.unwrap_err();
    assert!(matches!(err, zlicenser_server::Error::NotFound));
}

pub async fn test_payment_transaction(s: &dyn Storage, f: &Fixture) {
    let txn_id = uid();
    let txn = PaymentTransaction {
        id: txn_id,
        license_id: f.lic2_id,
        provider: PaymentProvider::Stripe,
        provider_transaction_id: "pi_123".to_string(),
        amount: 9900,
        currency: "EUR".to_string(),
        provider_tier: ProviderTier::Verified,
        test_mode: false,
        status: PaymentStatus::Pending,
        created_at: 1_000_000,
        confirmed_at: None,
    };
    s.create_payment_transaction(&txn).await.unwrap();
    let got = s.get_payment_transaction(txn_id).await.unwrap().unwrap();
    assert_eq!(got.status, PaymentStatus::Pending);

    let got = s
        .get_payment_transaction_for_license(f.lic2_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.provider_transaction_id, "pi_123");

    s.update_payment_status(txn_id, PaymentStatus::Confirmed, Some(1_500_000))
        .await
        .unwrap();
    let got = s.get_payment_transaction(txn_id).await.unwrap().unwrap();
    assert_eq!(got.status, PaymentStatus::Confirmed);
    assert_eq!(got.confirmed_at, Some(1_500_000));
}

pub async fn test_transfer_request(s: &dyn Storage, f: &Fixture) {
    let transfer_id = uid();
    let tr = TransferRequest {
        id: transfer_id,
        license_id: f.lic2_id,
        old_fingerprint_commitment: vec![0xaa; 32],
        new_fingerprint_commitment: vec![0xbb; 32],
        requested_at: 1_000_000,
        status: TransferStatus::Pending,
        vendor_note: None,
        resolved_at: None,
    };
    s.create_transfer_request(&tr).await.unwrap();
    let got = s.get_transfer_request(transfer_id).await.unwrap().unwrap();
    assert_eq!(got.status, TransferStatus::Pending);

    let reqs = s
        .list_transfer_requests_for_license(f.lic2_id)
        .await
        .unwrap();
    assert_eq!(reqs.len(), 1);

    s.resolve_transfer_request(
        transfer_id,
        TransferStatus::Approved,
        Some("looks good"),
        2_000_000,
    )
    .await
    .unwrap();
    let got = s.get_transfer_request(transfer_id).await.unwrap().unwrap();
    assert_eq!(got.status, TransferStatus::Approved);
    assert_eq!(got.vendor_note.as_deref(), Some("looks good"));
}

pub async fn test_session(s: &dyn Storage, f: &Fixture) {
    let b_id = uid();
    s.create_seat_binding(&make_seat_binding(b_id, f.lic2_id, vec![0xef; 32]))
        .await
        .unwrap();

    let sess_id = uid();
    let sess = make_session(sess_id, b_id);
    s.create_session(&sess).await.unwrap();
    let got = s.get_session(sess_id).await.unwrap().unwrap();
    assert_eq!(got.status, SessionStatus::Active);
    assert_eq!(got.seq_no, 0);

    let active = s
        .get_active_session_for_binding(b_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, sess_id);

    s.update_session_heartbeat(sess_id, 2_000_000, 1)
        .await
        .unwrap();
    let got = s.get_session(sess_id).await.unwrap().unwrap();
    assert_eq!(got.last_heartbeat_at, Some(2_000_000));
    assert_eq!(got.seq_no, 1);

    s.update_session_status(sess_id, SessionStatus::Suspect)
        .await
        .unwrap();
    let got = s.get_session(sess_id).await.unwrap().unwrap();
    assert_eq!(got.status, SessionStatus::Suspect);

    assert!(s
        .get_active_session_for_binding(b_id)
        .await
        .unwrap()
        .is_none());

    let sess2_id = uid();
    let sess2 = ActiveSession {
        id: sess2_id,
        binding_id: b_id,
        ephemeral_pubkey: vec![3u8; 32],
        issued_at: 1_000_000,
        expires_at: 1_100_000,
        last_heartbeat_at: None,
        seq_no: 0,
        status: SessionStatus::Active,
    };
    s.create_session(&sess2).await.unwrap();
    let affected = s.expire_sessions_before(2_000_000).await.unwrap();
    assert_eq!(affected, 1);
    let got = s.get_session(sess2_id).await.unwrap().unwrap();
    assert_eq!(got.status, SessionStatus::Expired);
}

pub async fn test_quarantine_case(s: &dyn Storage, f: &Fixture) {
    let sess_id = uid();
    s.create_session(&make_session(sess_id, f.binding_id))
        .await
        .unwrap();

    let qcase_id = uid();
    let qcase_case_id = uid();
    let qc = QuarantineCase {
        id: qcase_id,
        case_id: qcase_case_id,
        binding_id: f.binding_id,
        session_id: Some(sess_id),
        trigger: QuarantineTrigger::MissedHeartbeat,
        triggered_at: 2_000_000,
        status: QuarantineStatus::Active,
        resolution: None,
        resolved_at: None,
        vendor_note: None,
    };
    s.create_quarantine_case(&qc).await.unwrap();
    let got = s.get_quarantine_case(qcase_id).await.unwrap().unwrap();
    assert_eq!(got.trigger, QuarantineTrigger::MissedHeartbeat);

    let got = s
        .get_quarantine_case_by_case_id(qcase_case_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id, qcase_id);

    s.resolve_quarantine_case(
        qcase_id,
        QuarantineStatus::Resolved,
        Some("false positive"),
        3_000_000,
        Some("vendor reviewed"),
    )
    .await
    .unwrap();
    let got = s.get_quarantine_case(qcase_id).await.unwrap().unwrap();
    assert_eq!(got.status, QuarantineStatus::Resolved);
    assert_eq!(got.resolution.as_deref(), Some("false positive"));
}

pub async fn test_security_event(s: &dyn Storage, f: &Fixture) {
    let sess_id = uid();
    s.create_session(&make_session(sess_id, f.binding_id))
        .await
        .unwrap();

    let event_id = uid();
    let ev = SecurityEvent {
        id: 0,
        event_id,
        license_id: f.lic2_id,
        binding_id: f.binding_id,
        session_id: Some(sess_id),
        occurred_at_ns: 2_000_000_000,
        received_at_ns: 2_000_001_000,
        event_type: "HeartbeatMissed".to_string(),
        severity: SecurityEventSeverity::Warning,
        payload: "{}".to_string(),
        response: SecurityEventResponse::Warn,
        reviewed_by: None,
        reviewed_at: None,
        case_id: None,
    };
    s.create_security_event(&ev).await.unwrap();
    let events = s.get_security_events_for_license(f.lic2_id).await.unwrap();
    assert_eq!(events.len(), 1);
    let auto_id = events[0].id;
    assert!(auto_id > 0);

    s.mark_security_event_reviewed(auto_id, "admin", 3_000_000)
        .await
        .unwrap();
    let events = s.get_security_events_for_license(f.lic2_id).await.unwrap();
    assert_eq!(events[0].reviewed_by.as_deref(), Some("admin"));
}

pub async fn test_revocation_record(s: &dyn Storage, f: &Fixture) {
    s.update_license_status(
        f.lic2_id,
        LicenseStatus::Revoked,
        Some(3_000_000),
        Some("fraud"),
        None,
    )
    .await
    .unwrap();
    let rev = RevocationRecord {
        license_id: f.lic2_id,
        revoked_at: 3_000_000,
        revoked_by: RevocationSource::Api,
        reason: Some("fraud".to_string()),
    };
    s.create_revocation_record(&rev).await.unwrap();
    let got = s.get_revocation_record(f.lic2_id).await.unwrap().unwrap();
    assert_eq!(got.revoked_by, RevocationSource::Api);
    assert_eq!(got.reason.as_deref(), Some("fraud"));
}

pub async fn test_email_log(s: &dyn Storage, f: &Fixture) {
    let log_id = uid();
    let entry = EmailLogEntry {
        id: log_id,
        license_id: f.lic2_id,
        email_type: EmailType::GrantConfirmation,
        sent_to: "alice@example.com".to_string(),
        sent_at: 1_200_000,
        success: true,
        error_message: None,
    };
    s.create_email_log_entry(&entry).await.unwrap();
    let log = s.list_email_log_for_license(f.lic2_id).await.unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].email_type, EmailType::GrantConfirmation);
    assert!(log[0].success);
}

pub async fn test_enrollment_session_round_trip(s: &dyn Storage, f: &Fixture) {
    let sess_id = uid();
    let sess = make_enrollment_session(sess_id, f.prod_id);
    s.create_enrollment_session(&sess).await.unwrap();

    let got = s.get_enrollment_session(sess_id).await.unwrap().unwrap();
    assert_eq!(got.id, sess_id);
    assert_eq!(got.state, EnrollmentState::OfferPending);
    assert_eq!(got.fingerprint_commitment, vec![0xde; 32]);
    assert!(!got.payment_captured);
    assert_eq!(got.license_id, None);

    let update = EnrollmentSessionUpdate {
        state: Some(EnrollmentState::ReceiptPending),
        receipt_bytes: Some(vec![0xbe; 32]),
        updated_at: 2_000_000,
        ..Default::default()
    };
    s.update_enrollment_session(sess_id, 1_000_000, update)
        .await
        .unwrap();

    let got = s.get_enrollment_session(sess_id).await.unwrap().unwrap();
    assert_eq!(got.state, EnrollmentState::ReceiptPending);
    assert_eq!(got.receipt_bytes, Some(vec![0xbe; 32]));
    assert_eq!(got.updated_at, 2_000_000);
}

pub async fn test_session_webhook_lookup(s: &dyn Storage, f: &Fixture) {
    let sess_id = uid();
    let mut sess = make_enrollment_session(sess_id, f.prod_id);
    sess.payment_intent_id = Some("pi_test_abc".to_string());
    s.create_enrollment_session(&sess).await.unwrap();

    let found = s
        .get_session_by_payment_intent("pi_test_abc")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, sess_id);

    let none = s
        .get_session_by_payment_intent("pi_nonexistent")
        .await
        .unwrap();
    assert!(none.is_none());
}

pub async fn test_list_grant_ready_sessions(s: &dyn Storage, f: &Fixture) {
    let id1 = uid();
    let mut s1 = make_enrollment_session(id1, f.prod_id);
    s1.state = EnrollmentState::GrantReady;
    s.create_enrollment_session(&s1).await.unwrap();

    let id2 = uid();
    let s2 = make_enrollment_session(id2, f.prod_id);
    s.create_enrollment_session(&s2).await.unwrap();

    let ready = s.list_grant_ready_sessions().await.unwrap();
    assert!(ready.iter().any(|r| r.id == id1));
    assert!(!ready.iter().any(|r| r.id == id2));
}

pub async fn test_enrollment_session_optimistic_conflict(s: &dyn Storage, f: &Fixture) {
    let sess_id = uid();
    let sess = make_enrollment_session(sess_id, f.prod_id);
    s.create_enrollment_session(&sess).await.unwrap();

    let update = EnrollmentSessionUpdate {
        state: Some(EnrollmentState::PaymentHeld),
        updated_at: 2_000_000,
        ..Default::default()
    };
    let err = s
        .update_enrollment_session(sess_id, 9_999_999, update)
        .await
        .unwrap_err();
    assert!(matches!(err, zlicenser_server::Error::Conflict(_)));

    let got = s.get_enrollment_session(sess_id).await.unwrap().unwrap();
    assert_eq!(got.state, EnrollmentState::OfferPending);
}

pub mod issuance;

pub async fn test_transfer_pending_at(s: &dyn Storage, f: &Fixture) {
    let b_id = uid();
    let binding = make_seat_binding(b_id, f.lic_id, vec![0x12; 32]);
    s.create_seat_binding(&binding).await.unwrap();

    let count_before = s.count_transferable_seat_bindings(f.prod_id).await.unwrap();

    s.set_seat_binding_transfer_pending(b_id, Some(5_000_000))
        .await
        .unwrap();
    let count_after = s.count_transferable_seat_bindings(f.prod_id).await.unwrap();
    assert_eq!(count_after, count_before - 1);

    s.set_seat_binding_transfer_pending(b_id, None)
        .await
        .unwrap();
    let count_restored = s.count_transferable_seat_bindings(f.prod_id).await.unwrap();
    assert_eq!(count_restored, count_before);
}
