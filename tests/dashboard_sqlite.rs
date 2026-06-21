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
    async fn login_unknown_user_returns_401() {
        common::dashboard::test_login_unknown_user_returns_401().await;
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
    async fn login_deactivated_user_returns_401() {
        common::dashboard::test_login_deactivated_user_returns_401().await;
    }

    #[tokio::test]
    async fn key_session_has_owner_role() {
        common::dashboard::test_key_session_has_owner_role().await;
    }

    #[tokio::test]
    async fn password_session_has_correct_role() {
        common::dashboard::test_password_session_has_correct_role().await;
    }

    #[tokio::test]
    async fn session_info_includes_role_and_user_id() {
        common::dashboard::test_session_info_includes_role_and_user_id().await;
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
    async fn create_user_requires_key_sig() {
        common::dashboard::test_create_user_requires_key_sig().await;
    }

    #[tokio::test]
    async fn cannot_deactivate_self() {
        common::dashboard::test_cannot_deactivate_self().await;
    }

    #[tokio::test]
    async fn cannot_deactivate_last_owner() {
        common::dashboard::test_cannot_deactivate_last_owner().await;
    }

    #[tokio::test]
    async fn cannot_downgrade_last_owner_role() {
        common::dashboard::test_cannot_downgrade_last_owner_role().await;
    }

    #[tokio::test]
    async fn change_own_password_succeeds() {
        common::dashboard::test_change_own_password_succeeds().await;
    }

    #[tokio::test]
    async fn rbac_admin_cannot_manage_users() {
        common::dashboard::test_rbac_admin_cannot_manage_users().await;
    }

    #[tokio::test]
    async fn rbac_auditor_can_read_audit_log() {
        common::dashboard::test_rbac_auditor_can_read_audit_log().await;
    }

    #[tokio::test]
    async fn rbac_support_cannot_read_audit_log() {
        common::dashboard::test_rbac_support_cannot_read_audit_log().await;
    }

    #[tokio::test]
    async fn rbac_auditor_cannot_revoke_license() {
        common::dashboard::test_rbac_auditor_cannot_revoke_license().await;
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

    #[tokio::test]
    async fn unknown_route_returns_404_json() {
        common::dashboard::test_unknown_route_returns_404_json().await;
    }

    #[tokio::test]
    async fn post_without_content_type_returns_415_json() {
        common::dashboard::test_post_without_content_type_returns_415_json().await;
    }

    #[tokio::test]
    async fn invalid_json_returns_400_json() {
        common::dashboard::test_invalid_json_returns_400_json().await;
    }

    #[tokio::test]
    async fn json_missing_fields_returns_422_json() {
        common::dashboard::test_json_missing_fields_returns_422_json().await;
    }

    #[tokio::test]
    async fn invalid_path_param_returns_400_json() {
        common::dashboard::test_invalid_path_param_returns_400_json().await;
    }
}
