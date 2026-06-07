use std::sync::Arc;

use uuid::Uuid;

use super::handlers::now_ns;
use crate::storage::{
    Storage,
    types::{LicenseStatus, UpgradePolicy},
};

pub async fn handle_upgrade_activation<S: Storage>(
    storage: &Arc<S>,
    license_id: Uuid,
    to_bundle_version: &str,
) -> crate::Result<()> {
    let license = storage
        .get_license(license_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    if license.status != LicenseStatus::Active {
        return Err(crate::Error::InvalidTransition(format!(
            "license status is {}",
            license.status
        )));
    }

    if license.bundle_version == to_bundle_version {
        return Ok(());
    }

    let policy = storage
        .find_upgrade_policy(
            license.product_id,
            &license.bundle_version,
            to_bundle_version,
        )
        .await?;

    match policy.map(|p| p.policy) {
        Some(UpgradePolicy::AutoApprove | UpgradePolicy::FreeUpgrade) => {}
        Some(UpgradePolicy::RequireNewPurchase) => {
            return Err(crate::Error::InvalidTransition(
                "upgrade requires new purchase".to_owned(),
            ));
        }
        None => {
            return Err(crate::Error::InvalidTransition(
                "no upgrade policy found for this version transition".to_owned(),
            ));
        }
    }

    let new_license_id = Uuid::new_v4();
    let now = now_ns();

    storage
        .create_license(&crate::storage::types::License {
            id: new_license_id,
            customer_id: license.customer_id,
            product_id: license.product_id,
            bundle_version: to_bundle_version.to_owned(),
            connectivity_mode: license.connectivity_mode,
            seat_count: license.seat_count,
            expiry_at: license.expiry_at,
            status: LicenseStatus::Active,
            superseded_by: None,
            revoked_at: None,
            revocation_reason: None,
            created_at: now,
            email_sent_at: None,
        })
        .await?;

    storage
        .update_license_status(
            license_id,
            LicenseStatus::Superseded,
            None,
            None,
            Some(new_license_id),
        )
        .await?;

    Ok(())
}
