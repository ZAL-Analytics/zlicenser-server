mod common;

#[cfg(all(feature = "http-server", feature = "storage-postgres"))]
mod postgres {
    use std::sync::{Arc, OnceLock};

    use zlicenser_server::storage::PostgresStorage;

    use super::common;

    static BASE_URL: OnceLock<String> = OnceLock::new();

    fn base_url() -> &'static str {
        BASE_URL.get_or_init(|| {
            std::thread::spawn(|| {
                use testcontainers::runners::AsyncRunner;
                use testcontainers_modules::postgres::Postgres;
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let container = Box::leak(Box::new(Postgres::default().start().await.unwrap()));
                    let port = container.get_host_port_ipv4(5432).await.unwrap();
                    format!("postgres://postgres:postgres@127.0.0.1:{port}")
                })
            })
            .join()
            .unwrap()
        })
    }

    async fn store() -> PostgresStorage {
        let base = base_url();
        let db = format!("test_{}", uuid::Uuid::new_v4().simple());
        let admin = sqlx::PgPool::connect(&format!("{base}/postgres"))
            .await
            .unwrap();
        sqlx::query(&format!("CREATE DATABASE {db}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        PostgresStorage::new(&format!("{base}/{db}")).await.unwrap()
    }

    #[tokio::test]
    async fn health_200_ok() {
        let s = Arc::new(store().await);
        common::http::with_storage::test_health_200_ok_with(s).await;
    }

    #[tokio::test]
    async fn health_503_db_error() {
        common::http::with_storage::test_health_503_db_error().await;
    }

    #[tokio::test]
    async fn product_info_active_200() {
        let s = Arc::new(store().await);
        common::http::with_storage::test_product_info_active_200_with(s).await;
    }

    #[tokio::test]
    async fn product_info_inactive_404() {
        let s = Arc::new(store().await);
        common::http::with_storage::test_product_info_inactive_404_with(s).await;
    }

    #[tokio::test]
    async fn product_info_missing_404() {
        let s = Arc::new(store().await);
        common::http::with_storage::test_product_info_missing_404_with(s).await;
    }

    #[tokio::test]
    async fn product_info_terms_present() {
        let s = Arc::new(store().await);
        common::http::with_storage::test_product_info_terms_present_with(s).await;
    }

    #[tokio::test]
    async fn product_info_terms_absent() {
        let s = Arc::new(store().await);
        common::http::with_storage::test_product_info_terms_absent_with(s).await;
    }
}
