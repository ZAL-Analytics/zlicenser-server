#[cfg(feature = "payment-stripe")]
pub mod stripe;

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentTier {
    Verified,
    Pseudonymous,
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentStatus {
    RequiresCapture,
    Pending,
    RequiresAction,
    Failed,
    Cancelled,
    Succeeded,
}

pub struct PaymentMetadata {
    pub product_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub customer_email: Option<String>,
}

pub struct Money {
    pub amount: i64,
    pub currency: String,
}

pub struct PaymentIntent {
    pub intent_id: String,
    pub client_secret: String,
}

pub struct CaptureConfirmation {
    pub transaction_id: String,
    pub captured_at_ns: i64,
}

#[async_trait::async_trait]
pub trait PaymentProvider: Send + Sync {
    fn tier(&self) -> PaymentTier;
    fn is_payment_sandbox(&self) -> bool;

    async fn create_intent(&self, money: Money, metadata: PaymentMetadata)
    -> Result<PaymentIntent>;
    async fn get_intent_status(&self, intent_id: &str) -> Result<IntentStatus>;
    async fn capture_intent(&self, intent_id: &str) -> Result<CaptureConfirmation>;
    async fn cancel_intent(&self, intent_id: &str) -> Result<()>;
}
