use std::sync::Arc;

use uuid::Uuid;
use zlicenser_protocol::sessions::{SecurityEventReport, SecurityResponse, SecuritySeverity};

use crate::{
    issuance::handlers::HandlerContext,
    storage::{
        ActiveSessionUpdate, LicenseStatus, QuarantineCase, QuarantineTrigger, SecurityEventRecord,
        SessionStatus, Storage,
    },
};

use super::crypto;

pub(crate) async fn handle_security_event<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    report: SecurityEventReport,
    now_ns: i64,
) -> crate::Result<SecurityResponse> {
    // Idempotency: same event_id -> reconstruct and re-deliver the original response.
    if let Some(prior) = ctx
        .storage
        .get_security_event_by_event_id(report.event_id)
        .await?
    {
        return rebuild_response(ctx, &prior).await;
    }

    // Validate binding ownership; collapse all checks to a single error to prevent enumeration.
    let binding = ctx
        .storage
        .get_seat_binding(report.binding_id)
        .await?
        .filter(|b| b.license_id == report.license_id && b.revoked_at.is_none())
        .ok_or(crate::Error::BindingNotFound)?;

    let license = ctx
        .storage
        .get_license(report.license_id)
        .await?
        .filter(|l| l.status == LicenseStatus::Active)
        .ok_or(crate::Error::BindingNotFound)?;

    let product = ctx
        .storage
        .get_product(license.product_id)
        .await?
        .ok_or(crate::Error::BindingNotFound)?;

    let severity = report.event_type.default_severity();

    // If a vendor-initiated quarantine is already open, re-deliver it instead of opening a new case.
    let existing_case = ctx
        .storage
        .get_active_quarantine_case_for_binding(binding.id)
        .await?;

    if let Some(ref case) = existing_case
        && case.trigger == QuarantineTrigger::VendorAction
    {
        let session_seq_no = resolve_session_seq_no(ctx, report.session_id).await;
        let canonical = crypto::canonical_command_bytes(
            case.case_id,
            crypto::CMD_QUARANTINE,
            session_seq_no,
            &case.reason,
        );
        let vendor_sig = crypto::sign_command(&ctx.signing_key, &canonical);
        let shutdown = u32::try_from(product.shutdown_countdown_secs.unwrap_or(60)).unwrap_or(60);
        let response = SecurityResponse::Quarantine {
            reason: case.reason.clone(),
            case_id: case.case_id,
            shutdown_countdown_secs: shutdown,
            vendor_sig,
        };
        persist_event(
            ctx,
            &report,
            severity,
            "Quarantine",
            Some(case.case_id),
            now_ns,
        )
        .await?;
        return Ok(response);
    }

    let response = match severity {
        SecuritySeverity::Critical if product.auto_quarantine_on_critical => {
            let reason = format!(
                "Auto-quarantine: critical security event ({} bytes payload)",
                serde_json::to_string(&report.event_type).map_or(0, |s| s.len())
            );
            let shutdown =
                u32::try_from(product.shutdown_countdown_secs.unwrap_or(60)).unwrap_or(60);
            quarantine_response(ctx, &report, binding.id, &reason, shutdown, now_ns).await?
        }
        SecuritySeverity::Critical | SecuritySeverity::Warning => SecurityResponse::Warn {
            message_to_show_user: warn_message_for_event(&report.event_type),
        },
        SecuritySeverity::Info => SecurityResponse::Log,
    };

    let (response_type, case_id) = match &response {
        SecurityResponse::Log => ("Log", None),
        SecurityResponse::Warn { .. } => ("Warn", None),
        SecurityResponse::Quarantine { case_id, .. } => ("Quarantine", Some(*case_id)),
        SecurityResponse::Terminate { case_id, .. } => ("Terminate", Some(*case_id)),
    };

    persist_event(ctx, &report, severity, response_type, case_id, now_ns).await?;

    Ok(response)
}

/// Creates a quarantine case, transitions the session if live, and returns the signed response.
async fn quarantine_response<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    report: &SecurityEventReport,
    binding_id: Uuid,
    reason: &str,
    shutdown_countdown_secs: u32,
    now_ns: i64,
) -> crate::Result<SecurityResponse> {
    let event_id = report.event_id;
    let case_id = Uuid::new_v4();

    let session_seq_no = resolve_session_seq_no(ctx, report.session_id).await;

    ctx.storage
        .create_quarantine_case(&QuarantineCase {
            id: Uuid::new_v4(),
            case_id,
            binding_id,
            session_id: report.session_id,
            trigger: QuarantineTrigger::SecurityEvent,
            trigger_event_id: Some(event_id),
            reason: reason.to_owned(),
            created_at: now_ns,
            resumed_at: None,
        })
        .await?;

    // Transition any live session to Quarantined.
    if let Some(session_id) = report.session_id
        && let Ok(Some(session)) = ctx.storage.get_session(session_id).await
        && matches!(
            session.status,
            SessionStatus::Active | SessionStatus::Suspect
        )
    {
        let _ = ctx
            .storage
            .update_active_session(
                session.id,
                session.updated_at,
                ActiveSessionUpdate {
                    status: Some(SessionStatus::Quarantined),
                    updated_at: now_ns,
                    ..Default::default()
                },
            )
            .await;
    }

    let canonical =
        crypto::canonical_command_bytes(case_id, crypto::CMD_QUARANTINE, session_seq_no, reason);
    let vendor_sig = crypto::sign_command(&ctx.signing_key, &canonical);

    Ok(SecurityResponse::Quarantine {
        reason: reason.to_owned(),
        case_id,
        shutdown_countdown_secs,
        vendor_sig,
    })
}

async fn persist_event<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    report: &SecurityEventReport,
    severity: SecuritySeverity,
    response_type: &str,
    case_id: Option<Uuid>,
    now_ns: i64,
) -> crate::Result<()> {
    let severity_str = match severity {
        SecuritySeverity::Info => "Info",
        SecuritySeverity::Warning => "Warning",
        SecuritySeverity::Critical => "Critical",
    };
    ctx.storage
        .create_security_event(&SecurityEventRecord {
            id: 0,
            event_id: report.event_id,
            license_id: report.license_id,
            binding_id: report.binding_id,
            session_id: report.session_id,
            occurred_at_ns: report.occurred_at_ns,
            received_at_ns: now_ns,
            event_type: event_type_tag(&report.event_type),
            payload: serde_json::to_string(&report.event_type).unwrap_or_default(),
            severity: severity_str.into(),
            response_type: response_type.into(),
            case_id,
            reviewed_at: None,
        })
        .await
}

/// Reconstructs the original `SecurityResponse` from a persisted record.
async fn rebuild_response<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    record: &SecurityEventRecord,
) -> crate::Result<SecurityResponse> {
    match record.response_type.as_str() {
        "Log" => Ok(SecurityResponse::Log),
        "Warn" => Ok(SecurityResponse::Warn {
            message_to_show_user: record.payload.clone(),
        }),
        "Quarantine" => {
            let case_id = record.case_id.ok_or(crate::Error::Corrupt(
                "quarantine record missing case_id".into(),
            ))?;
            let case = ctx
                .storage
                .get_quarantine_case_by_case_id(case_id)
                .await?
                .ok_or(crate::Error::Corrupt("quarantine case not found".into()))?;
            let seq_no = resolve_session_seq_no(ctx, record.session_id).await;
            let canonical = crypto::canonical_command_bytes(
                case_id,
                crypto::CMD_QUARANTINE,
                seq_no,
                &case.reason,
            );
            let vendor_sig = crypto::sign_command(&ctx.signing_key, &canonical);
            // Fetch shutdown_countdown from product if available, otherwise use spec default.
            let shutdown_countdown_secs = product_shutdown_secs(ctx, record.license_id).await;
            Ok(SecurityResponse::Quarantine {
                reason: case.reason,
                case_id,
                shutdown_countdown_secs,
                vendor_sig,
            })
        }
        "Terminate" => {
            let case_id = record.case_id.ok_or(crate::Error::Corrupt(
                "terminate record missing case_id".into(),
            ))?;
            let case = ctx
                .storage
                .get_quarantine_case_by_case_id(case_id)
                .await?
                .ok_or(crate::Error::Corrupt("quarantine case not found".into()))?;
            let seq_no = resolve_session_seq_no(ctx, record.session_id).await;
            let canonical = crypto::canonical_command_bytes(
                case_id,
                crypto::CMD_TERMINATE,
                seq_no,
                &case.reason,
            );
            let vendor_sig = crypto::sign_command(&ctx.signing_key, &canonical);
            Ok(SecurityResponse::Terminate {
                reason: case.reason,
                case_id,
                vendor_sig,
            })
        }
        other => Err(crate::Error::Corrupt(format!(
            "unknown response_type in security event record: {other}"
        ))),
    }
}

// Returns the current seq_no for a session, or 0 if the session is absent or inaccessible.
async fn resolve_session_seq_no<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    session_id: Option<Uuid>,
) -> u64 {
    let Some(id) = session_id else { return 0 };
    ctx.storage
        .get_session(id)
        .await
        .ok()
        .flatten()
        .map_or(0, |s| s.seq_no)
}

async fn product_shutdown_secs<S: Storage>(ctx: &Arc<HandlerContext<S>>, license_id: Uuid) -> u32 {
    let Ok(Some(license)) = ctx.storage.get_license(license_id).await else {
        return 60;
    };
    u32::try_from(
        ctx.storage
            .get_product(license.product_id)
            .await
            .ok()
            .flatten()
            .and_then(|p| p.shutdown_countdown_secs)
            .unwrap_or(60),
    )
    .unwrap_or(60)
}

fn warn_message_for_event(event: &zlicenser_protocol::sessions::SecurityEventType) -> String {
    use zlicenser_protocol::sessions::SecurityEventType;
    match event {
        SecurityEventType::PtraceAttempted { from_pid } => {
            format!("ptrace attempt detected from PID {from_pid}")
        }
        SecurityEventType::DebuggerDetected { method } => {
            format!("debugger detected via {method}")
        }
        SecurityEventType::UnexpectedParentProcess { parent_name, .. } => {
            format!("unexpected parent process: {parent_name}")
        }
        SecurityEventType::MemoryMappingAnomaly { region, flags } => {
            format!("memory mapping anomaly in region {region} (flags: {flags})")
        }
        SecurityEventType::VmDetected {
            hypervisor_signature,
        } => {
            format!("VM environment detected: {hypervisor_signature}")
        }
        SecurityEventType::SuspiciousEnvironmentVar { key } => {
            format!("suspicious environment variable: {key}")
        }
        SecurityEventType::FingerprintDrift {
            delta_score,
            threshold,
        } => {
            format!("fingerprint drift: score {delta_score:.2} (threshold {threshold:.2})")
        }
        SecurityEventType::FingerprintExceededThreshold { delta_score } => {
            format!("fingerprint threshold exceeded: score {delta_score:.2}")
        }
        SecurityEventType::HeartbeatSequenceGap { expected, received } => {
            format!("heartbeat sequence gap: expected {expected}, received {received}")
        }
        SecurityEventType::MultipleSessionsDetected => {
            "multiple concurrent sessions detected".into()
        }
        SecurityEventType::UnexpectedChildFork => "unexpected child process forked".into(),
        SecurityEventType::AbnormalExitSignal { signal } => {
            format!("abnormal exit signal {signal}")
        }
    }
}

/// Returns the discriminant tag string for a `SecurityEventType` variant.
fn event_type_tag(event: &zlicenser_protocol::sessions::SecurityEventType) -> String {
    use zlicenser_protocol::sessions::SecurityEventType;
    match event {
        SecurityEventType::PtraceAttempted { .. } => "PtraceAttempted",
        SecurityEventType::DebuggerDetected { .. } => "DebuggerDetected",
        SecurityEventType::UnexpectedParentProcess { .. } => "UnexpectedParentProcess",
        SecurityEventType::MemoryMappingAnomaly { .. } => "MemoryMappingAnomaly",
        SecurityEventType::VmDetected { .. } => "VmDetected",
        SecurityEventType::SuspiciousEnvironmentVar { .. } => "SuspiciousEnvironmentVar",
        SecurityEventType::FingerprintDrift { .. } => "FingerprintDrift",
        SecurityEventType::FingerprintExceededThreshold { .. } => "FingerprintExceededThreshold",
        SecurityEventType::HeartbeatSequenceGap { .. } => "HeartbeatSequenceGap",
        SecurityEventType::MultipleSessionsDetected => "MultipleSessionsDetected",
        SecurityEventType::UnexpectedChildFork => "UnexpectedChildFork",
        SecurityEventType::AbnormalExitSignal { .. } => "AbnormalExitSignal",
    }
    .into()
}
