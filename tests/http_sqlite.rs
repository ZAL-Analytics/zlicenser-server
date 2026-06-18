mod common;

#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
mod sqlite {
    use super::common;

    #[tokio::test]
    async fn health_200_ok() {
        common::http::test_health_200_ok().await;
    }

    #[tokio::test]
    async fn health_503_db_error() {
        common::http::test_health_503_db_error().await;
    }

    #[tokio::test]
    async fn product_info_active_200() {
        common::http::test_product_info_active_200().await;
    }

    #[tokio::test]
    async fn product_info_inactive_404() {
        common::http::test_product_info_inactive_404().await;
    }

    #[tokio::test]
    async fn product_info_missing_404() {
        common::http::test_product_info_missing_404().await;
    }

    #[tokio::test]
    async fn product_info_terms_present() {
        common::http::test_product_info_terms_present().await;
    }

    #[tokio::test]
    async fn product_info_terms_absent() {
        common::http::test_product_info_terms_absent().await;
    }
}
