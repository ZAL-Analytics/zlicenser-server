use std::sync::Arc;

#[async_trait::async_trait]
pub trait TsaProvider: Send + Sync {
    async fn timestamp(&self, digest: &[u8; 32]) -> crate::Result<Vec<u8>>;
}

#[cfg(feature = "tsa-qtsa")]
pub struct QtsaTsaProvider {
    client: reqwest::Client,
    url: String,
}

#[cfg(feature = "tsa-qtsa")]
impl QtsaTsaProvider {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }
}

#[cfg(feature = "tsa-qtsa")]
#[async_trait::async_trait]
impl TsaProvider for QtsaTsaProvider {
    async fn timestamp(&self, digest: &[u8; 32]) -> crate::Result<Vec<u8>> {
        zlicenser_protocol::tsa::providers::qtsa::request_token_hashed_to(
            &self.client,
            digest,
            &self.url,
        )
        .await
        .map_err(|e| crate::Error::TsaFailed(e.to_string()))
    }
}

pub(crate) async fn tsa_with_retry(
    tsa: &Arc<dyn TsaProvider>,
    digest: &[u8; 32],
    max_attempts: u32,
) -> crate::Result<Vec<u8>> {
    let mut delay = tokio::time::Duration::from_secs(1);
    for attempt in 0..max_attempts {
        match tsa.timestamp(digest).await {
            Ok(token) => return Ok(token),
            Err(e) if attempt + 1 < max_attempts => {
                tracing::warn!(attempt, error = %e, "TSA failed; retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}
