use std::sync::Arc;

use uuid::Uuid;

use crate::{issuance::handlers::HandlerContext, storage::Storage};

// Records a grace-period check-in, updating `last_verified_at` on the binding.
#[allow(dead_code)]
pub(crate) async fn record_grace_checkin<S: Storage>(
    ctx: &Arc<HandlerContext<S>>,
    binding_id: Uuid,
    now_ns: i64,
) -> crate::Result<()> {
    ctx.storage
        .update_seat_binding_verified(binding_id, now_ns)
        .await
}
