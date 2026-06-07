mod common;

#[cfg(feature = "storage-sqlite")]
mod sqlite {
    use std::sync::Arc;

    use super::common;
    use zlicenser_server::storage::SqliteStorage;

    async fn store() -> Arc<SqliteStorage> {
        Arc::new(SqliteStorage::in_memory().await.unwrap())
    }

    #[tokio::test]
    async fn enroll_happy_path() {
        let s = store().await;
        common::issuance::test_enroll_happy_path(s).await;
    }

    #[tokio::test]
    async fn enroll_idempotent() {
        let s = store().await;
        common::issuance::test_enroll_idempotent(s).await;
    }

    #[tokio::test]
    async fn enroll_offer_expired() {
        let s = store().await;
        common::issuance::test_enroll_offer_expired(s).await;
    }

    #[tokio::test]
    async fn enroll_nonce_mismatch() {
        let s = store().await;
        common::issuance::test_enroll_nonce_mismatch(s).await;
    }

    #[tokio::test]
    async fn enroll_bad_signature() {
        let s = store().await;
        common::issuance::test_enroll_bad_signature(s).await;
    }

    #[tokio::test]
    async fn enroll_payment_not_held() {
        let s = store().await;
        common::issuance::test_enroll_payment_not_held(s).await;
    }

    #[tokio::test]
    async fn enroll_tsa_failure() {
        let s = store().await;
        common::issuance::test_enroll_tsa_failure(s).await;
    }

    #[tokio::test]
    async fn revoke_license() {
        let s = store().await;
        common::issuance::test_revoke_license(s).await;
    }

    #[tokio::test]
    async fn transfer_approve() {
        let s = store().await;
        common::issuance::test_transfer_approve(s).await;
    }

    #[tokio::test]
    async fn transfer_reject() {
        let s = store().await;
        common::issuance::test_transfer_reject(s).await;
    }

    #[tokio::test]
    async fn upgrade_free() {
        let s = store().await;
        common::issuance::test_upgrade_free(s).await;
    }

    #[tokio::test]
    async fn upgrade_same_version_noop() {
        let s = store().await;
        common::issuance::test_upgrade_same_version_noop(s).await;
    }
}
