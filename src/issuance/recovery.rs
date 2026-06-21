use super::handlers::{
    HandlerContext, deserialize_grant, deserialize_receipt, empty_receipt, issue_all_records,
    now_ns, upsert_customer,
};
use super::secrets::SIssue;
use crate::storage::{
    Storage,
    types::{EnrollmentSession, EnrollmentSessionUpdate, EnrollmentState},
};

pub async fn startup_recovery_sweep<S: Storage>(ctx: &HandlerContext<S>) -> crate::Result<()> {
    let sessions = ctx.storage.list_grant_ready_sessions().await?;
    for session in sessions {
        if let Err(e) = recover_issue(ctx, &session).await {
            tracing::error!(session_id = %session.id, error = %e, "recovery failed");
        }
    }
    Ok(())
}

async fn recover_issue<S: Storage>(
    ctx: &HandlerContext<S>,
    session: &EnrollmentSession,
) -> crate::Result<()> {
    if session.state != EnrollmentState::GrantReady {
        return Ok(());
    }

    let grant_bytes = session
        .grant_bytes
        .as_deref()
        .ok_or_else(|| crate::Error::Corrupt("GrantReady session missing grant_bytes".into()))?;
    let grant = deserialize_grant(grant_bytes)?;
    let license_id = grant.license_id;

    if ctx.storage.get_license(license_id).await?.is_some() {
        let now = now_ns();
        if let Err(e) = ctx
            .storage
            .update_enrollment_session(
                session.id,
                0,
                EnrollmentSessionUpdate {
                    state: Some(EnrollmentState::Issued),
                    payment_captured: Some(true),
                    license_id: Some(Some(license_id)),
                    updated_at: now,
                    ..Default::default()
                },
            )
            .await
        {
            tracing::warn!(session_id = %session.id, error = %e, "failed to mark already-issued session as Issued during recovery");
        }
        return Ok(());
    }

    let product = ctx
        .storage
        .get_product(session.product_id)
        .await?
        .ok_or(crate::Error::NotFound)?;

    let customer = upsert_customer(&ctx.storage, session).await?;

    let receipt = session
        .receipt_bytes
        .as_deref()
        .and_then(|b| deserialize_receipt(b).ok());
    let fallback = empty_receipt();
    let receipt_ref = receipt.as_ref().unwrap_or(&fallback);

    let payment_sandbox = ctx.payment.is_payment_sandbox();
    let payment_tier = match ctx.payment.tier() {
        crate::payment::PaymentTier::Verified => crate::storage::types::ProviderTier::Verified,
        crate::payment::PaymentTier::Pseudonymous => {
            crate::storage::types::ProviderTier::Pseudonymous
        }
        crate::payment::PaymentTier::Anonymous => crate::storage::types::ProviderTier::Anonymous,
    };

    let confirmation = crate::payment::CaptureConfirmation {
        transaction_id: session
            .payment_intent_id
            .clone()
            .unwrap_or_else(|| "recovered".to_owned()),
        captured_at_ns: now_ns(),
    };

    issue_all_records(
        &ctx.storage,
        &ctx.at_rest_key,
        session,
        &product,
        &customer,
        receipt_ref,
        &grant.binding_cert,
        &grant.tsa_token,
        &confirmation,
        license_id,
        i64::from(grant.binding_cert.seat_index),
        grant.binding_cert.expiry_at_ns,
        session.id,
        payment_sandbox,
        payment_tier,
        SIssue::generate(),
    )
    .await?;

    if let Some(transport) = &ctx.email {
        let t = transport.clone();
        tokio::spawn(async move {
            if let Err(e) = t.send_grant_confirmation(license_id).await {
                tracing::warn!(license_id = %license_id, error = %e, "failed to send grant confirmation email during recovery");
            }
        });
    }

    Ok(())
}
