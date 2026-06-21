use crate::storage::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    UsersManage,
    VendorRead,
    ProductsWrite,
    ProductsRead,
    TermsWrite,
    TermsRead,
    CustomersRead,
    LicensesRead,
    LicensesRevoke,
    TransfersDecide,
    SecurityRead,
    SecurityRespond,
    AuditRead,
}

impl Role {
    pub fn has(self, perm: Permission) -> bool {
        match self {
            Role::Owner => true,
            Role::Admin => !matches!(perm, Permission::UsersManage),
            Role::Support => matches!(
                perm,
                Permission::ProductsRead
                    | Permission::TermsRead
                    | Permission::CustomersRead
                    | Permission::LicensesRead
                    | Permission::LicensesRevoke
                    | Permission::TransfersDecide
                    | Permission::SecurityRead
                    | Permission::SecurityRespond
            ),
            Role::ProductManager => matches!(
                perm,
                Permission::ProductsWrite
                    | Permission::ProductsRead
                    | Permission::TermsWrite
                    | Permission::TermsRead
                    | Permission::CustomersRead
                    | Permission::LicensesRead
            ),
            Role::Auditor => matches!(
                perm,
                Permission::ProductsRead
                    | Permission::TermsRead
                    | Permission::CustomersRead
                    | Permission::LicensesRead
                    | Permission::SecurityRead
                    | Permission::AuditRead
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_has_all_permissions() {
        let perms = [
            Permission::UsersManage,
            Permission::VendorRead,
            Permission::ProductsWrite,
            Permission::ProductsRead,
            Permission::TermsWrite,
            Permission::TermsRead,
            Permission::CustomersRead,
            Permission::LicensesRead,
            Permission::LicensesRevoke,
            Permission::TransfersDecide,
            Permission::SecurityRead,
            Permission::SecurityRespond,
            Permission::AuditRead,
        ];
        for perm in perms {
            assert!(Role::Owner.has(perm), "Owner should have {perm:?}");
        }
    }

    #[test]
    fn admin_lacks_users_manage() {
        assert!(!Role::Admin.has(Permission::UsersManage));
    }

    #[test]
    fn admin_has_all_except_users_manage() {
        let perms = [
            Permission::VendorRead,
            Permission::ProductsWrite,
            Permission::ProductsRead,
            Permission::TermsWrite,
            Permission::TermsRead,
            Permission::CustomersRead,
            Permission::LicensesRead,
            Permission::LicensesRevoke,
            Permission::TransfersDecide,
            Permission::SecurityRead,
            Permission::SecurityRespond,
            Permission::AuditRead,
        ];
        for perm in perms {
            assert!(Role::Admin.has(perm), "Admin should have {perm:?}");
        }
    }

    #[test]
    fn support_permissions() {
        assert!(Role::Support.has(Permission::ProductsRead));
        assert!(Role::Support.has(Permission::TermsRead));
        assert!(Role::Support.has(Permission::CustomersRead));
        assert!(Role::Support.has(Permission::LicensesRead));
        assert!(Role::Support.has(Permission::LicensesRevoke));
        assert!(Role::Support.has(Permission::TransfersDecide));
        assert!(Role::Support.has(Permission::SecurityRead));
        assert!(Role::Support.has(Permission::SecurityRespond));

        assert!(!Role::Support.has(Permission::UsersManage));
        assert!(!Role::Support.has(Permission::VendorRead));
        assert!(!Role::Support.has(Permission::ProductsWrite));
        assert!(!Role::Support.has(Permission::TermsWrite));
        assert!(!Role::Support.has(Permission::AuditRead));
    }

    #[test]
    fn product_manager_permissions() {
        assert!(Role::ProductManager.has(Permission::ProductsWrite));
        assert!(Role::ProductManager.has(Permission::ProductsRead));
        assert!(Role::ProductManager.has(Permission::TermsWrite));
        assert!(Role::ProductManager.has(Permission::TermsRead));
        assert!(Role::ProductManager.has(Permission::CustomersRead));
        assert!(Role::ProductManager.has(Permission::LicensesRead));

        assert!(!Role::ProductManager.has(Permission::UsersManage));
        assert!(!Role::ProductManager.has(Permission::VendorRead));
        assert!(!Role::ProductManager.has(Permission::LicensesRevoke));
        assert!(!Role::ProductManager.has(Permission::TransfersDecide));
        assert!(!Role::ProductManager.has(Permission::SecurityRead));
        assert!(!Role::ProductManager.has(Permission::SecurityRespond));
        assert!(!Role::ProductManager.has(Permission::AuditRead));
    }

    #[test]
    fn auditor_permissions() {
        assert!(Role::Auditor.has(Permission::ProductsRead));
        assert!(Role::Auditor.has(Permission::TermsRead));
        assert!(Role::Auditor.has(Permission::CustomersRead));
        assert!(Role::Auditor.has(Permission::LicensesRead));
        assert!(Role::Auditor.has(Permission::SecurityRead));
        assert!(Role::Auditor.has(Permission::AuditRead));

        assert!(!Role::Auditor.has(Permission::UsersManage));
        assert!(!Role::Auditor.has(Permission::VendorRead));
        assert!(!Role::Auditor.has(Permission::ProductsWrite));
        assert!(!Role::Auditor.has(Permission::TermsWrite));
        assert!(!Role::Auditor.has(Permission::LicensesRevoke));
        assert!(!Role::Auditor.has(Permission::TransfersDecide));
        assert!(!Role::Auditor.has(Permission::SecurityRespond));
    }
}
