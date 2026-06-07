mod common;

#[cfg(feature = "storage-postgres")]
mod postgres {
    use std::sync::{Arc, OnceLock};

    use super::common;
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

    async fn store() -> Arc<PostgresStorage> {
        let base = base_url();
        let db = format!("issuance_{}", uuid::Uuid::new_v4().simple());
        let admin = sqlx::PgPool::connect(&format!("{}/postgres", base))
            .await
            .unwrap();
        sqlx::query(&format!("CREATE DATABASE {db}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        Arc::new(
            PostgresStorage::new(&format!("{}/{}", base, db))
                .await
                .unwrap(),
        )
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
