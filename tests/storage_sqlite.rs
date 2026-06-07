mod common;

#[cfg(feature = "storage-sqlite")]
mod sqlite {
    use super::common;
    use zlicenser_server::storage::SqliteStorage;

    async fn store() -> SqliteStorage {
        SqliteStorage::in_memory().await.unwrap()
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
}
