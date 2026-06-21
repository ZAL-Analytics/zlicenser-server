use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::storage::{AuditAuthMethod, Role, Storage};

const SESSION_TTL: Duration = Duration::from_hours(8);
const CHALLENGE_TTL: Duration = Duration::from_mins(1);

struct SessionRecord {
    auth_method: AuditAuthMethod,
    expires_at: Instant,
    user_id: Option<Uuid>,
    role: Role,
}

pub struct DashboardAuthManager {
    challenges: Mutex<HashMap<String, Instant>>,
    sessions: Mutex<HashMap<String, SessionRecord>>,
}

impl DashboardAuthManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            challenges: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub async fn new_challenge(&self) -> String {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let nonce = B64.encode(buf);
        let mut map = self.challenges.lock().await;
        map.retain(|_, exp| *exp > Instant::now());
        map.insert(nonce.clone(), Instant::now() + CHALLENGE_TTL);
        nonce
    }

    pub async fn consume_challenge(&self, nonce: &str) -> bool {
        let mut map = self.challenges.lock().await;
        map.remove(nonce).is_some_and(|exp| exp > Instant::now())
    }

    pub async fn new_session(
        &self,
        auth_method: AuditAuthMethod,
        user_id: Option<Uuid>,
        role: Role,
    ) -> String {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let token = B64.encode(buf);
        let mut map = self.sessions.lock().await;
        map.retain(|_, r| r.expires_at > Instant::now());
        map.insert(
            token.clone(),
            SessionRecord {
                auth_method,
                expires_at: Instant::now() + SESSION_TTL,
                user_id,
                role,
            },
        );
        token
    }

    pub async fn invalidate_session(&self, token: &str) {
        self.sessions.lock().await.remove(token);
    }

    pub async fn session_auth_method(&self, token: &str) -> Option<AuditAuthMethod> {
        let map = self.sessions.lock().await;
        map.get(token).and_then(|r| {
            if r.expires_at > Instant::now() {
                Some(r.auth_method)
            } else {
                None
            }
        })
    }

    pub async fn session_expires_at(&self, token: &str) -> Option<Instant> {
        let map = self.sessions.lock().await;
        map.get(token).and_then(|r| {
            if r.expires_at > Instant::now() {
                Some(r.expires_at)
            } else {
                None
            }
        })
    }

    pub async fn session_user_id(&self, token: &str) -> Option<Option<Uuid>> {
        let map = self.sessions.lock().await;
        map.get(token).and_then(|r| {
            if r.expires_at > Instant::now() {
                Some(r.user_id)
            } else {
                None
            }
        })
    }

    pub async fn session_role(&self, token: &str) -> Option<Role> {
        let map = self.sessions.lock().await;
        map.get(token).and_then(|r| {
            if r.expires_at > Instant::now() {
                Some(r.role)
            } else {
                None
            }
        })
    }
}

pub struct DashboardState<S> {
    pub storage: Arc<S>,
    pub auth: Arc<DashboardAuthManager>,
    pub verifying_key: VerifyingKey,
    pub payment_sandbox: bool,
}

impl<S: Storage + Clone + Send + Sync + 'static> DashboardState<S> {
    pub fn new(storage: Arc<S>, verifying_key: VerifyingKey, payment_sandbox: bool) -> Arc<Self> {
        Arc::new(Self {
            storage,
            auth: DashboardAuthManager::new(),
            verifying_key,
            payment_sandbox,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn challenge_consumed_once() {
        let mgr = DashboardAuthManager::new();
        let nonce = mgr.new_challenge().await;
        assert!(mgr.consume_challenge(&nonce).await);
        assert!(!mgr.consume_challenge(&nonce).await);
    }

    #[tokio::test]
    async fn session_invalid_after_invalidation() {
        let mgr = DashboardAuthManager::new();
        let token = mgr
            .new_session(AuditAuthMethod::KeyBased, None, Role::Owner)
            .await;
        assert!(mgr.session_auth_method(&token).await.is_some());
        mgr.invalidate_session(&token).await;
        assert!(mgr.session_auth_method(&token).await.is_none());
    }

    #[tokio::test]
    async fn unknown_token_returns_none() {
        let mgr = DashboardAuthManager::new();
        assert!(mgr.session_auth_method("not-a-token").await.is_none());
    }

    #[tokio::test]
    async fn session_carries_user_id_and_role() {
        let mgr = DashboardAuthManager::new();
        let uid = Uuid::new_v4();
        let token = mgr
            .new_session(AuditAuthMethod::Password, Some(uid), Role::Support)
            .await;
        assert_eq!(mgr.session_user_id(&token).await, Some(Some(uid)));
        assert_eq!(mgr.session_role(&token).await, Some(Role::Support));
    }

    #[tokio::test]
    async fn key_session_carries_no_user_id_and_owner_role() {
        let mgr = DashboardAuthManager::new();
        let token = mgr
            .new_session(AuditAuthMethod::KeyBased, None, Role::Owner)
            .await;
        assert_eq!(mgr.session_user_id(&token).await, Some(None));
        assert_eq!(mgr.session_role(&token).await, Some(Role::Owner));
    }
}
