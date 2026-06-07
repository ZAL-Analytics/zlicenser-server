use std::sync::Arc;

use uuid::Uuid;

use super::handlers::now_ns;
use crate::storage::{
    types::{LicenseStatus, RevocationRecord, RevocationSource},
    Storage,
};

pub async fn revoke_license<S: Storage>(
    storage: &Arc<S>,
    license_id: Uuid,
    reason: Option<String>,
    source: RevocationSource,
) -> crate::Result<()> {
    let license = storage
        .get_license(license_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    if license.status == LicenseStatus::Revoked {
        return Ok(());
    }

    let now = now_ns();

    storage
        .update_license_status(
            license_id,
            LicenseStatus::Revoked,
            Some(now),
            reason.as_deref(),
            None,
        )
        .await?;

    storage
        .create_revocation_record(&RevocationRecord {
            license_id,
            revoked_at: now,
            revoked_by: source,
            reason,
        })
        .await?;

    Ok(())
}
