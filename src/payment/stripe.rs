use reqwest::Client as HttpClient;
use serde_json::Value;

use super::{
    CaptureConfirmation, IntentStatus, Money, PaymentIntent, PaymentMetadata, PaymentProvider,
    PaymentTier,
};
use crate::Result;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

pub struct StripePaymentProvider {
    client: HttpClient,
    secret_key: String,
    test_mode: bool,
}

impl StripePaymentProvider {
    pub fn new(secret_key: &str) -> Self {
        let test_mode = secret_key.starts_with("sk_test_");
        Self {
            client: HttpClient::new(),
            secret_key: secret_key.to_owned(),
            test_mode,
        }
    }

    async fn api_post(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> std::result::Result<Value, String> {
        let url = format!("{STRIPE_API_BASE}/{path}");
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.secret_key, Some(""))
            .form(form)
            .send()
            .await
            .map_err(|e| format!("stripe: {e}"))?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| format!("stripe: {e}"))?;
        if !status.is_success() {
            let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
            return Err(format!("stripe: {msg}"));
        }
        Ok(body)
    }

    async fn api_get(&self, path: &str) -> std::result::Result<Value, String> {
        let url = format!("{STRIPE_API_BASE}/{path}");
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.secret_key, Some(""))
            .send()
            .await
            .map_err(|e| format!("stripe: {e}"))?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| format!("stripe: {e}"))?;
        if !status.is_success() {
            let msg = body["error"]["message"].as_str().unwrap_or("unknown error");
            return Err(format!("stripe: {msg}"));
        }
        Ok(body)
    }
}

#[async_trait::async_trait]
impl PaymentProvider for StripePaymentProvider {
    fn tier(&self) -> PaymentTier {
        PaymentTier::Verified
    }

    fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    async fn create_intent(
        &self,
        money: Money,
        _metadata: PaymentMetadata,
    ) -> Result<PaymentIntent> {
        let amount = money.amount.to_string();
        let currency = money.currency.to_lowercase();
        let body = self
            .api_post(
                "payment_intents",
                &[
                    ("amount", amount.as_str()),
                    ("currency", currency.as_str()),
                    ("capture_method", "manual"),
                ],
            )
            .await
            .map_err(crate::Error::Database)?;
        let intent_id = body["id"]
            .as_str()
            .ok_or_else(|| crate::Error::Database("stripe: missing id".into()))?
            .to_owned();
        let client_secret = body["client_secret"]
            .as_str()
            .ok_or_else(|| crate::Error::Database("stripe: missing client_secret".into()))?
            .to_owned();
        Ok(PaymentIntent {
            intent_id,
            client_secret,
        })
    }

    async fn get_intent_status(&self, intent_id: &str) -> Result<IntentStatus> {
        let body = self
            .api_get(&format!("payment_intents/{intent_id}"))
            .await
            .map_err(crate::Error::Database)?;
        Ok(match body["status"].as_str().unwrap_or("") {
            "requires_capture" => IntentStatus::RequiresCapture,
            "processing" | "requires_action" => IntentStatus::Pending,
            "requires_payment_method" => IntentStatus::RequiresAction,
            "canceled" => IntentStatus::Cancelled,
            "succeeded" => IntentStatus::Succeeded,
            _ => IntentStatus::Failed,
        })
    }

    async fn capture_intent(&self, intent_id: &str) -> Result<CaptureConfirmation> {
        if matches!(
            self.get_intent_status(intent_id).await?,
            IntentStatus::Succeeded
        ) {
            return Ok(CaptureConfirmation {
                transaction_id: intent_id.to_string(),
                captured_at_ns: now_ns(),
            });
        }
        self.api_post(&format!("payment_intents/{intent_id}/capture"), &[])
            .await
            .map_err(crate::Error::PaymentCaptureFailed)?;
        Ok(CaptureConfirmation {
            transaction_id: intent_id.to_string(),
            captured_at_ns: now_ns(),
        })
    }

    async fn cancel_intent(&self, intent_id: &str) -> Result<()> {
        if matches!(
            self.get_intent_status(intent_id).await?,
            IntentStatus::Cancelled
        ) {
            return Ok(());
        }
        self.api_post(&format!("payment_intents/{intent_id}/cancel"), &[])
            .await
            .map_err(crate::Error::PaymentCancelFailed)?;
        Ok(())
    }
}

fn now_ns() -> i64 {
    // Nanoseconds since epoch wraps in year 2262; safe for all practical purposes.
    #[allow(clippy::cast_possible_truncation)]
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;
    ns
}
