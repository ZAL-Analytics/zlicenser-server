mod common;

#[cfg(all(feature = "http-server", feature = "storage-sqlite"))]
mod sqlite {
    use super::common;

    #[tokio::test]
    async fn challenge_returns_nonce() {
        common::dashboard::test_challenge_returns_nonce().await;
    }

    #[tokio::test]
    async fn challenge_nonces_are_unique() {
        common::dashboard::test_challenge_nonces_are_unique().await;
    }

    #[tokio::test]
    async fn verify_with_valid_key_returns_token() {
        common::dashboard::test_verify_with_valid_key_returns_token().await;
    }

    #[tokio::test]
    async fn verify_with_invalid_sig_returns_401() {
        common::dashboard::test_verify_with_invalid_sig_returns_401().await;
    }

    #[tokio::test]
    async fn verify_with_wrong_key_returns_401() {
        common::dashboard::test_verify_with_wrong_key_returns_401().await;
    }

    #[tokio::test]
    async fn login_no_password_configured_returns_403() {
        common::dashboard::test_login_no_password_configured_returns_403().await;
    }

    #[tokio::test]
    async fn login_correct_password_returns_token() {
        common::dashboard::test_login_correct_password_returns_token().await;
    }

    #[tokio::test]
    async fn login_wrong_password_returns_401() {
        common::dashboard::test_login_wrong_password_returns_401().await;
    }

    #[tokio::test]
    async fn protected_route_without_token_returns_401() {
        common::dashboard::test_protected_route_without_token_returns_401().await;
    }

    #[tokio::test]
    async fn session_info_with_valid_token() {
        common::dashboard::test_session_info_with_valid_token().await;
    }

    #[tokio::test]
    async fn logout_invalidates_token() {
        common::dashboard::test_logout_invalidates_token().await;
    }

    #[tokio::test]
    async fn list_products_returns_empty_ok() {
        common::dashboard::test_list_products_returns_empty_ok().await;
    }

    #[tokio::test]
    async fn create_and_get_product() {
        common::dashboard::test_create_and_get_product().await;
    }

    #[tokio::test]
    async fn vendor_not_configured_returns_404() {
        common::dashboard::test_vendor_not_configured_returns_404().await;
    }

    #[tokio::test]
    async fn vendor_configured_returns_200() {
        common::dashboard::test_vendor_configured_returns_200().await;
    }

    #[tokio::test]
    async fn list_customers_returns_empty_ok() {
        common::dashboard::test_list_customers_returns_empty_ok().await;
    }

    #[tokio::test]
    async fn list_licenses_returns_empty_ok() {
        common::dashboard::test_list_licenses_returns_empty_ok().await;
    }

    #[tokio::test]
    async fn list_transfers_returns_empty_ok() {
        common::dashboard::test_list_transfers_returns_empty_ok().await;
    }

    #[tokio::test]
    async fn list_security_events_returns_empty_ok() {
        common::dashboard::test_list_security_events_returns_empty_ok().await;
    }

    #[tokio::test]
    async fn audit_log_returns_empty_ok() {
        common::dashboard::test_audit_log_returns_empty_ok().await;
    }
}
