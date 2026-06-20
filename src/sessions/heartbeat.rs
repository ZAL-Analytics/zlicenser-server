use std::sync::Arc;

use uuid::Uuid;
use zlicenser_protocol::sessions::{Heartbeat, HeartbeatAck, HeartbeatStatus};

use crate::{
    issuance::handlers::HandlerContext,
    storage::{
        ActiveSession, ActiveSessionUpdate, PendingCommand, QuarantineCase, QuarantineTrigger,
        SecurityEventRecord, SessionStatus, Storage,
    },
};

use super::crypto;

#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_heartbeat<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    hb: Heartbeat,
    now_ns: i64,
) -> crate::Result<HeartbeatAck> {
    let session = ctx
        .storage
        .get_session(hb.session_id)
        .await?
        .ok_or(crate::Error::ActiveSessionNotFound)?;

    match session.status {
        SessionStatus::Expired => return Err(crate::Error::SessionExpired),
        SessionStatus::Terminated => return Err(crate::Error::SessionTerminated),
        _ => {}
    }

    // Vendor-quarantined fast path: rotate token, do not advance seq_no.
    if session.status == SessionStatus::Quarantined
        && session.command_pending != Some(PendingCommand::Resume)
    {
        let case = ctx
            .storage
            .get_active_quarantine_case_for_session(session.id)
            .await?;
        let new_token = crypto::generate_session_token();
        ctx.storage
            .update_active_session(
                session.id,
                session.updated_at,
                ActiveSessionUpdate {
                    session_token: Some(new_token),
                    updated_at: now_ns,
                    ..Default::default()
                },
            )
            .await?;
        let (case_id, vendor_sig) = sign_quarantine(ctx, case.as_ref(), &session);
        return Ok(HeartbeatAck {
            seq_no: session.seq_no,
            new_session_token: new_token,
            status: HeartbeatStatus::Quarantine {
                case_id,
                vendor_sig,
            },
        });
    }

    // Session-level expiry.
    if now_ns >= session.expires_at {
        ctx.storage
            .update_active_session(
                session.id,
                session.updated_at,
                ActiveSessionUpdate {
                    status: Some(SessionStatus::Expired),
                    updated_at: now_ns,
                    ..Default::default()
                },
            )
            .await?;
        return Err(crate::Error::SessionExpired);
    }

    // Lazy missed-heartbeat evaluation (Active/Suspect only).
    let elapsed_ns = session
        .last_heartbeat_at
        .map_or(0, |last| now_ns.saturating_sub(last));
    let interval_ns = i64::from(session.heartbeat_interval_secs) * 1_000_000_000;
    let grace_ns = i64::from(session.heartbeat_grace_secs) * 1_000_000_000;

    if session.last_heartbeat_at.is_some()
        && matches!(
            session.status,
            SessionStatus::Active | SessionStatus::Suspect
        )
        && elapsed_ns > interval_ns + grace_ns
    {
        return quarantine_session(
            ctx,
            &session,
            QuarantineTrigger::MissedHeartbeat,
            None,
            "Missed heartbeat: exceeded grace period".into(),
            now_ns,
        )
        .await;
    }

    // Token check.
    if !crypto::verify_session_token(&session.session_token, &hb.session_token) {
        return Err(crate::Error::SessionTokenMismatch);
    }

    let hmac_key = crypto::decrypt_hmac_key(&session.session_hmac_key_encrypted, &ctx.at_rest_key)?;

    // Sequence gap check, emits a security event and may auto-quarantine.
    let expected_seq = session.seq_no + 1;
    let warn_message = if hb.seq_no == expected_seq {
        None
    } else {
        let product = ctx
            .storage
            .get_product(session.product_id)
            .await?
            .ok_or(crate::Error::NotFound)?;

        let event_id = Uuid::new_v4();
        emit_seq_gap_event(ctx, &session, event_id, expected_seq, hb.seq_no, now_ns).await?;

        if product.auto_quarantine_on_critical {
            return quarantine_session(
                ctx,
                &session,
                QuarantineTrigger::SecurityEvent,
                Some(event_id),
                format!(
                    "Heartbeat sequence gap: expected {expected_seq}, got {}",
                    hb.seq_no
                ),
                now_ns,
            )
            .await;
        }

        Some(format!(
            "Heartbeat sequence gap: expected {expected_seq}, received {}",
            hb.seq_no
        ))
    };

    // HMAC verification.
    if !crypto::verify_heartbeat_hmac(
        &hmac_key,
        hb.session_id,
        hb.seq_no,
        &hb.session_token,
        &hb.fingerprint_commitment,
        &hb.hmac,
    ) {
        return Err(crate::Error::HeartbeatHmacFailed);
    }

    let new_token = crypto::generate_session_token();

    // Deliver any pending vendor command.
    if let Some(cmd) = session.command_pending {
        match cmd {
            PendingCommand::Terminate => {
                let case = ctx
                    .storage
                    .get_active_quarantine_case_for_session(session.id)
                    .await?;
                let (case_id, vendor_sig) = sign_terminate(ctx, case.as_ref(), &session);
                ctx.storage
                    .update_active_session(
                        session.id,
                        session.updated_at,
                        ActiveSessionUpdate {
                            status: Some(SessionStatus::Terminated),
                            command_pending: Some(None),
                            session_token: Some(new_token),
                            seq_no: Some(hb.seq_no),
                            last_heartbeat_at: Some(now_ns),
                            updated_at: now_ns,
                        },
                    )
                    .await?;
                return Ok(HeartbeatAck {
                    seq_no: hb.seq_no,
                    new_session_token: new_token,
                    status: HeartbeatStatus::Terminate {
                        case_id,
                        vendor_sig,
                    },
                });
            }
            PendingCommand::Resume => {
                ctx.storage
                    .update_active_session(
                        session.id,
                        session.updated_at,
                        ActiveSessionUpdate {
                            status: Some(SessionStatus::Active),
                            command_pending: Some(None),
                            session_token: Some(new_token),
                            seq_no: Some(hb.seq_no),
                            last_heartbeat_at: Some(now_ns),
                            updated_at: now_ns,
                        },
                    )
                    .await?;
                ctx.storage
                    .update_seat_binding_verified(session.binding_id, now_ns)
                    .await?;
                return Ok(HeartbeatAck {
                    seq_no: hb.seq_no,
                    new_session_token: new_token,
                    status: HeartbeatStatus::Resume,
                });
            }
        }
    }

    // Determine new session status based on heartbeat timing.
    let new_status = if session.last_heartbeat_at.is_some() && elapsed_ns > interval_ns {
        SessionStatus::Suspect
    } else {
        SessionStatus::Active
    };

    ctx.storage
        .update_active_session(
            session.id,
            session.updated_at,
            ActiveSessionUpdate {
                status: Some(new_status),
                session_token: Some(new_token),
                seq_no: Some(hb.seq_no),
                last_heartbeat_at: Some(now_ns),
                updated_at: now_ns,
                ..Default::default()
            },
        )
        .await?;

    ctx.storage
        .update_seat_binding_verified(session.binding_id, now_ns)
        .await?;

    let status = match warn_message {
        Some(message) => HeartbeatStatus::Warn { message },
        None => HeartbeatStatus::Continue,
    };

    Ok(HeartbeatAck {
        seq_no: hb.seq_no,
        new_session_token: new_token,
        status,
    })
}

/// Creates a quarantine case, transitions the session, and returns the ack.
async fn quarantine_session<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    session: &ActiveSession,
    trigger: QuarantineTrigger,
    trigger_event_id: Option<Uuid>,
    reason: String,
    now_ns: i64,
) -> crate::Result<HeartbeatAck> {
    let case_id = Uuid::new_v4();
    ctx.storage
        .create_quarantine_case(&QuarantineCase {
            id: Uuid::new_v4(),
            case_id,
            binding_id: session.binding_id,
            session_id: Some(session.id),
            trigger,
            trigger_event_id,
            reason: reason.clone(),
            created_at: now_ns,
            resumed_at: None,
        })
        .await?;

    let new_token = crypto::generate_session_token();
    ctx.storage
        .update_active_session(
            session.id,
            session.updated_at,
            ActiveSessionUpdate {
                status: Some(SessionStatus::Quarantined),
                session_token: Some(new_token),
                updated_at: now_ns,
                ..Default::default()
            },
        )
        .await?;

    let canonical =
        crypto::canonical_command_bytes(case_id, crypto::CMD_QUARANTINE, session.seq_no, &reason);
    let vendor_sig = crypto::sign_command(&ctx.signing_key, &canonical);

    Ok(HeartbeatAck {
        seq_no: session.seq_no,
        new_session_token: new_token,
        status: HeartbeatStatus::Quarantine {
            case_id,
            vendor_sig,
        },
    })
}

/// Signs a quarantine delivery using the active case, or a zero signature for edge cases.
fn sign_quarantine<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    case: Option<&QuarantineCase>,
    session: &ActiveSession,
) -> (Uuid, [u8; 64]) {
    match case {
        Some(c) => {
            let canonical = crypto::canonical_command_bytes(
                c.case_id,
                crypto::CMD_QUARANTINE,
                session.seq_no,
                &c.reason,
            );
            (
                c.case_id,
                crypto::sign_command(&ctx.signing_key, &canonical),
            )
        }
        // Session is quarantined but no open case exists, should not occur in normal operation.
        None => (Uuid::new_v4(), [0u8; 64]),
    }
}

/// Signs a terminate delivery using the active case, or a zero signature for edge cases.
fn sign_terminate<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    case: Option<&QuarantineCase>,
    session: &ActiveSession,
) -> (Uuid, [u8; 64]) {
    match case {
        Some(c) => {
            let canonical = crypto::canonical_command_bytes(
                c.case_id,
                crypto::CMD_TERMINATE,
                session.seq_no,
                &c.reason,
            );
            (
                c.case_id,
                crypto::sign_command(&ctx.signing_key, &canonical),
            )
        }
        None => (Uuid::nil(), [0u8; 64]),
    }
}

/// Persists a `HeartbeatSequenceGap` security event record.
async fn emit_seq_gap_event<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    session: &ActiveSession,
    event_id: Uuid,
    expected: u64,
    received: u64,
    now_ns: i64,
) -> crate::Result<()> {
    use zlicenser_protocol::sessions::SecurityEventType;
    let event_type = SecurityEventType::HeartbeatSequenceGap { expected, received };
    ctx.storage
        .create_security_event(&SecurityEventRecord {
            id: 0,
            event_id,
            license_id: session.license_id,
            binding_id: session.binding_id,
            session_id: Some(session.id),
            occurred_at_ns: now_ns,
            received_at_ns: now_ns,
            event_type: "HeartbeatSequenceGap".into(),
            payload: serde_json::to_string(&event_type).unwrap_or_default(),
            severity: "Warning".into(),
            response_type: "Log".into(),
            case_id: None,
            reviewed_at: None,
            false_positive_at: None,
        })
        .await
}
