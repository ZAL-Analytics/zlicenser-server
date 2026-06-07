use uuid::Uuid;

#[async_trait::async_trait]
pub trait EmailTransport: Send + Sync {
    async fn send_grant_confirmation(&self, license_id: Uuid) -> crate::Result<()>;
}

pub struct NoopEmailTransport;

#[async_trait::async_trait]
impl EmailTransport for NoopEmailTransport {
    async fn send_grant_confirmation(&self, _license_id: Uuid) -> crate::Result<()> {
        Ok(())
    }
}
