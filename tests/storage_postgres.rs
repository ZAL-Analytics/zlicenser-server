mod common;

#[cfg(feature = "storage-postgres")]
mod postgres {
    use super::common;
    use std::sync::OnceLock;
    use zlicenser_server::storage::PostgresStorage;

    static BASE_URL: OnceLock<String> = OnceLock::new();

    fn base_url() -> &'static str {
        BASE_URL.get_or_init(|| {
            std::thread::spawn(|| {
                use testcontainers::runners::AsyncRunner;
                use testcontainers_modules::postgres::Postgres;
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let container = Box::leak(Box::new(Postgres::default().start().await.unwrap()));
                    let port = container.get_host_port_ipv4(5432).await.unwrap();
                    format!("postgres://postgres:postgres@127.0.0.1:{}", port)
                })
            })
            .join()
            .unwrap()
        })
    }

    async fn store() -> PostgresStorage {
        let base = base_url();
        let db = format!("test_{}", uuid::Uuid::new_v4().simple());
        let admin = sqlx::PgPool::connect(&format!("{}/postgres", base))
            .await
            .unwrap();
        sqlx::query(&format!("CREATE DATABASE {db}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        PostgresStorage::new(&format!("{}/{}", base, db))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn vendor_config() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_vendor_config(&s, &f).await;
    }

    #[tokio::test]
    async fn product() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_product(&s, &f).await;
    }

    #[tokio::test]
    async fn term_declaration() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_term_declaration(&s, &f).await;
    }

    #[tokio::test]
    async fn terms_documents() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_terms_documents(&s, &f).await;
    }

    #[tokio::test]
    async fn customer_fields() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_customer_fields(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policies() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policies(&s, &f).await;
    }

    #[tokio::test]
    async fn customer() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_customer(&s, &f).await;
    }

    #[tokio::test]
    async fn license() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_license(&s, &f).await;
    }

    #[tokio::test]
    async fn consent_record() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_consent_record(&s, &f).await;
    }

    #[tokio::test]
    async fn seat_binding() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_seat_binding(&s, &f).await;
    }

    #[tokio::test]
    async fn issuance_secret() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_issuance_secret(&s, &f).await;
    }

    #[tokio::test]
    async fn payment_transaction() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_payment_transaction(&s, &f).await;
    }

    #[tokio::test]
    async fn transfer_request() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_transfer_request(&s, &f).await;
    }

    #[tokio::test]
    async fn session() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_session(&s, &f).await;
    }

    #[tokio::test]
    async fn quarantine_case() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_quarantine_case(&s, &f).await;
    }

    #[tokio::test]
    async fn security_event() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_security_event(&s, &f).await;
    }

    #[tokio::test]
    async fn revocation_record() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_revocation_record(&s, &f).await;
    }

    #[tokio::test]
    async fn email_log() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_email_log(&s, &f).await;
    }

    #[tokio::test]
    async fn enrollment_session_round_trip() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_enrollment_session_round_trip(&s, &f).await;
    }

    #[tokio::test]
    async fn session_webhook_lookup() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_session_webhook_lookup(&s, &f).await;
    }

    #[tokio::test]
    async fn list_grant_ready_sessions() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_list_grant_ready_sessions(&s, &f).await;
    }

    #[tokio::test]
    async fn enrollment_session_optimistic_conflict() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_enrollment_session_optimistic_conflict(&s, &f).await;
    }

    #[tokio::test]
    async fn transfer_pending_at() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_transfer_pending_at(&s, &f).await;
    }

    #[tokio::test]
    async fn activation_gate_missing_declarations() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_activation_gate_missing_declarations(&s, &f).await;
    }

    #[tokio::test]
    async fn activation_gate_document_not_ready() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_activation_gate_document_not_ready(&s, &f).await;
    }

    #[tokio::test]
    async fn activation_gate_customer_fields_invalid() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_activation_gate_customer_fields_invalid(&s, &f).await;
    }

    #[tokio::test]
    async fn activation_gate_document_not_activated() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_activation_gate_document_not_activated(&s, &f).await;
    }

    #[tokio::test]
    async fn activation_gate_succeeds_when_all_conditions_met() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_activation_gate_succeeds_when_all_conditions_met(&s, &f).await;
    }

    #[tokio::test]
    async fn terms_document_conflict_blocks_activation() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_terms_document_conflict_blocks_activation(&s, &f).await;
    }

    #[tokio::test]
    async fn terms_document_warnings_require_acknowledgment() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_terms_document_warnings_require_acknowledgment(&s, &f).await;
    }

    #[tokio::test]
    async fn terms_document_warnings_acknowledged_can_activate() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_terms_document_warnings_acknowledged_can_activate(&s, &f).await;
    }

    #[tokio::test]
    async fn terms_document_valid_activates_immediately() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_terms_document_valid_activates_immediately(&s, &f).await;
    }

    #[tokio::test]
    async fn term_declaration_valid_values_accepted() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_term_declaration_valid_values_accepted(&s, &f).await;
    }

    #[tokio::test]
    async fn term_declaration_invalid_value_rejected() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_term_declaration_invalid_value_rejected(&s, &f).await;
    }

    #[tokio::test]
    async fn customer_fields_national_id_requires_legal_obligation() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_customer_fields_national_id_requires_legal_obligation(&s, &f).await;
    }

    #[tokio::test]
    async fn customer_fields_legitimate_interest_requires_purpose() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_customer_fields_legitimate_interest_requires_purpose(&s, &f).await;
    }

    #[tokio::test]
    async fn customer_fields_unknown_key_rejected() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_customer_fields_unknown_key_rejected(&s, &f).await;
    }

    #[tokio::test]
    async fn field_value_phone_e164_valid_and_invalid() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_field_value_phone_e164_valid_and_invalid(&s, &f).await;
    }

    #[tokio::test]
    async fn field_value_eu_vat_valid_and_invalid() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_field_value_eu_vat_valid_and_invalid(&s, &f).await;
    }

    #[tokio::test]
    async fn field_value_date_of_birth_age_gate() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_field_value_date_of_birth_age_gate(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policy_exact_beats_wildcard() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policy_exact_beats_wildcard(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policy_wildcard_fallback() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policy_wildcard_fallback(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policy_no_match_returns_none() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policy_no_match_returns_none(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policy_tie_broken_by_creation_order() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policy_tie_broken_by_creation_order(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policy_invalid_from_version_rejected() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policy_invalid_from_version_rejected(&s, &f).await;
    }

    #[tokio::test]
    async fn upgrade_policy_invalid_to_version_rejected() {
        let s = store().await;
        let f = common::setup(&s).await;
        common::test_upgrade_policy_invalid_to_version_rejected(&s, &f).await;
    }
}
