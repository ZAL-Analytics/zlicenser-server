use uuid::Uuid;

use crate::storage::{AuditAction, AuditAuthMethod, AuditEntry, AuditStore, AuditTargetType};

pub fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub fn format_rfc3339(epoch_secs: u64) -> String {
    let s = epoch_secs % 60;
    let total_min = epoch_secs / 60;
    let mi = total_min % 60;
    let total_hours = total_min / 60;
    let h = total_hours % 24;
    let total_days = total_hours / 24;

    let mut year = 1970u64;
    let mut days = total_days;
    loop {
        let yd = days_in_year(year);
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }

    let mut month = 1u64;
    loop {
        let md = days_in_month(year, month);
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        days + 1,
        h,
        mi,
        s
    )
}

pub fn format_ns_as_rfc3339(ns: i64) -> String {
    let epoch_secs = u64::try_from(ns / 1_000_000_000).unwrap_or_default();
    format_rfc3339(epoch_secs)
}

#[allow(clippy::manual_is_multiple_of)]
fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_year(y: u64) -> u64 {
    if is_leap(y) { 366 } else { 365 }
}

fn days_in_month(y: u64, m: u64) -> u64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

pub fn parse_iso_ns(s: &str) -> Option<i64> {
    let trimmed = s.trim_end_matches('Z');
    let parts: Vec<&str> = trimmed.splitn(2, 'T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return None;
    }
    let (y, mo, d) = (date_parts[0], date_parts[1], date_parts[2]);
    let (h, mi, sec) = (time_parts[0], time_parts[1], time_parts[2]);

    let mut days = 0u64;
    for yr in 1970..y {
        days += days_in_year(yr);
    }
    for m in 1..mo {
        days += days_in_month(y, m);
    }
    days += d - 1;

    let epoch_secs = days * 86400 + h * 3600 + mi * 60 + sec;
    i64::try_from(epoch_secs * 1_000_000_000).ok()
}

pub fn new_audit_entry(
    auth_method: AuditAuthMethod,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: Option<Uuid>,
    detail: Option<String>,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        occurred_at: now_ns(),
        auth_method,
        action,
        target_type,
        target_id,
        detail,
    }
}

pub async fn append_audit<S: AuditStore>(storage: &S, entry: AuditEntry) {
    let _ = storage.append_audit_entry(&entry).await;
}
