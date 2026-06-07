use std::sync::Arc;

use uuid::Uuid;

use super::handlers::now_ns;
use crate::storage::{
    Storage,
    types::{TransferPolicy, TransferRequest, TransferStatus},
};

pub async fn request_transfer<S: Storage>(
    storage: &Arc<S>,
    license_id: Uuid,
    old_fingerprint_commitment: Vec<u8>,
    new_fingerprint_commitment: Vec<u8>,
) -> crate::Result<TransferRequest> {
    let license = storage
        .get_license(license_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    let product = storage
        .get_product(license.product_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    match product.transfer_policy {
        TransferPolicy::NotAvailable => return Err(crate::Error::RevocationNotSupported),
        TransferPolicy::VendorApproval => {}
    }

    let existing = storage
        .find_seat_binding_by_commitment(license_id, &old_fingerprint_commitment)
        .await?
        .ok_or(crate::Error::BindingNotFound)?;

    if existing.transfer_pending_at.is_some() {
        return Err(crate::Error::TransferAlreadyPending);
    }

    let now = now_ns();

    storage
        .set_seat_binding_transfer_pending(existing.id, Some(now))
        .await?;

    let req = TransferRequest {
        id: Uuid::new_v4(),
        license_id,
        old_fingerprint_commitment,
        new_fingerprint_commitment,
        requested_at: now,
        status: TransferStatus::Pending,
        vendor_note: None,
        resolved_at: None,
    };

    storage.create_transfer_request(&req).await?;

    Ok(req)
}

pub async fn approve_transfer<S: Storage>(
    storage: &Arc<S>,
    transfer_id: Uuid,
    vendor_note: Option<String>,
) -> crate::Result<()> {
    let transfer = storage
        .get_transfer_request(transfer_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    if transfer.status != TransferStatus::Pending {
        return Err(crate::Error::InvalidTransition(format!(
            "transfer status is {}",
            transfer.status
        )));
    }

    let old_binding = storage
        .find_seat_binding_by_commitment(transfer.license_id, &transfer.old_fingerprint_commitment)
        .await?
        .ok_or(crate::Error::BindingNotFound)?;

    let now = now_ns();

    storage
        .set_seat_binding_transfer_pending(old_binding.id, None)
        .await?;

    storage
        .create_seat_binding(&crate::storage::types::FingerprintSeatBinding {
            id: Uuid::new_v4(),
            license_id: transfer.license_id,
            fingerprint_commitment: transfer.new_fingerprint_commitment.clone(),
            seat_index: old_binding.seat_index,
            bound_at: now,
            last_verified_at: None,
            revoked_at: None,
            transfer_pending_at: None,
        })
        .await?;

    storage.revoke_seat_binding(old_binding.id, now).await?;

    storage
        .resolve_transfer_request(
            transfer_id,
            TransferStatus::Approved,
            vendor_note.as_deref(),
            now,
        )
        .await?;

    Ok(())
}

pub async fn reject_transfer<S: Storage>(
    storage: &Arc<S>,
    transfer_id: Uuid,
    vendor_note: Option<String>,
) -> crate::Result<()> {
    let transfer = storage
        .get_transfer_request(transfer_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    if transfer.status != TransferStatus::Pending {
        return Err(crate::Error::InvalidTransition(format!(
            "transfer status is {}",
            transfer.status
        )));
    }

    let binding = storage
        .find_seat_binding_by_commitment(transfer.license_id, &transfer.old_fingerprint_commitment)
        .await?
        .ok_or(crate::Error::BindingNotFound)?;

    let now = now_ns();

    storage
        .set_seat_binding_transfer_pending(binding.id, None)
        .await?;

    storage
        .resolve_transfer_request(
            transfer_id,
            TransferStatus::Rejected,
            vendor_note.as_deref(),
            now,
        )
        .await?;

    Ok(())
}
