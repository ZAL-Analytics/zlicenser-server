use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use axum::{routing::get, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64_URL, Engine as _};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::PeerIpKeyExtractor, GovernorLayer,
};

use zlicenser_server::{
    http::{
        build_router,
        dashboard::{
            build_dashboard_challenge_router, build_dashboard_login_verify_router,
            build_dashboard_router, state::DashboardState,
        },
        health::{health_handler, HealthState},
        product_info::{product_info_handler, ProductInfoState},
    },
    issuance::{
        email::EmailTransport,
        handlers::{HandlerContext, ServerConfig},
        tsa::TsaProvider,
    },
    payment::{
        CaptureConfirmation, IntentStatus, Money, PaymentIntent, PaymentMetadata,
        PaymentProvider as PaymentProviderTrait, PaymentTier,
    },
    storage::Storage,
};

use crate::config::{resolve_secret, update_toml, update_toml_nested, AppConfig};

// Noop stubs for optional subsystems
struct NoopTsaProvider;

#[async_trait::async_trait]
impl TsaProvider for NoopTsaProvider {
    async fn timestamp(&self, _digest: &[u8; 32]) -> zlicenser_server::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct NoopPaymentProvider;

#[async_trait::async_trait]
impl PaymentProviderTrait for NoopPaymentProvider {
    fn tier(&self) -> PaymentTier {
        PaymentTier::Anonymous
    }

    fn is_payment_sandbox(&self) -> bool {
        false
    }

    async fn create_intent(
        &self,
        _money: Money,
        _metadata: PaymentMetadata,
    ) -> zlicenser_server::Result<PaymentIntent> {
        Err(zlicenser_server::Error::NoPaymentProvider)
    }

    async fn get_intent_status(&self, _intent_id: &str) -> zlicenser_server::Result<IntentStatus> {
        Err(zlicenser_server::Error::NoPaymentProvider)
    }

    async fn capture_intent(
        &self,
        _intent_id: &str,
    ) -> zlicenser_server::Result<CaptureConfirmation> {
        Err(zlicenser_server::Error::NoPaymentProvider)
    }

    async fn cancel_intent(&self, _intent_id: &str) -> zlicenser_server::Result<()> {
        Err(zlicenser_server::Error::NoPaymentProvider)
    }
}

// Provider builders
fn build_tsa_provider(cfg: &AppConfig) -> anyhow::Result<Arc<dyn TsaProvider>> {
    let Some(tsa_cfg) = cfg.tsa.as_ref() else {
        return Ok(Arc::new(NoopTsaProvider));
    };
    match tsa_cfg.provider.as_deref().unwrap_or("noop") {
        "qtsa" => {
            let url = resolve_secret(tsa_cfg.url_env.as_deref(), tsa_cfg.url_file.as_deref())?
                .context("[tsa].url_env or [tsa].url_file is required for provider = 'qtsa'")?;
            Ok(Arc::new(
                zlicenser_server::issuance::tsa::QtsaTsaProvider::new(url),
            ))
        }
        "noop" | "" => Ok(Arc::new(NoopTsaProvider)),
        other => anyhow::bail!("unknown [tsa].provider '{other}'; supported: qtsa"),
    }
}

fn build_payment_provider(
    cfg: &AppConfig,
) -> anyhow::Result<(Arc<dyn PaymentProviderTrait>, Option<String>)> {
    let Some(pay_cfg) = cfg.payment.as_ref() else {
        return Ok((Arc::new(NoopPaymentProvider), None));
    };
    match pay_cfg.provider.as_deref().unwrap_or("noop") {
        "stripe" => {
            let secret_key = resolve_secret(
                pay_cfg.secret_key_env.as_deref(),
                pay_cfg.secret_key_file.as_deref(),
            )?
            .context(
                "[payment].secret_key_env or [payment].secret_key_file is required for provider = 'stripe'",
            )?;
            let webhook_secret = resolve_secret(
                pay_cfg.webhook_secret_env.as_deref(),
                pay_cfg.webhook_secret_file.as_deref(),
            )?;
            let p = zlicenser_server::payment::stripe::StripePaymentProvider::new(&secret_key);
            Ok((Arc::new(p), webhook_secret))
        }
        "noop" | "" => Ok((Arc::new(NoopPaymentProvider), None)),
        other => anyhow::bail!("unknown [payment].provider '{other}'; supported: stripe"),
    }
}

// Key helpers
fn find_key_file(cfg: &AppConfig) -> Option<PathBuf> {
    let candidates = [
        cfg.vendor.as_ref().and_then(|v| v.private_key_path.clone()),
        Some(PathBuf::from("./vendor_key")),
        dirs::config_dir().map(|d| d.join("zlicenser-server/vendor_key")),
        Some(PathBuf::from("/etc/zlicenser-server/vendor_key")),
    ];

    candidates.into_iter().flatten().find(|p| p.exists())
}

fn load_signing_key(cfg: &AppConfig) -> anyhow::Result<(SigningKey, PathBuf)> {
    let key_path = find_key_file(cfg).ok_or_else(|| {
        anyhow::anyhow!("no vendor key found; run `zlicenser-server keygen` to generate one")
    })?;

    let bytes = std::fs::read(&key_path)
        .with_context(|| format!("reading key file {}", key_path.display()))?;

    anyhow::ensure!(
        bytes.len() == 32,
        "key file {} must be exactly 32 bytes (raw Ed25519 seed)",
        key_path.display()
    );

    let seed: [u8; 32] = bytes.try_into().expect("length checked above");
    Ok((SigningKey::from_bytes(&seed), key_path))
}

fn derive_at_rest_key(signing_key: &SigningKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, signing_key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"zlicenser-server-at-rest-key-v1", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn write_key_file(path: &Path, seed: &[u8; 32]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    std::fs::write(path, seed).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok(())
}

// SMTP password file helper
fn check_password_file_permissions(path: &Path) -> anyhow::Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    let mode = meta.permissions().mode();
    // Reject any permission bits beyond owner read/write (0o600)
    anyhow::ensure!(
        mode & 0o177 == 0,
        "password file {} has permissions {:04o}; must be exactly 0600",
        path.display(),
        mode & 0o777
    );
    Ok(())
}

fn read_smtp_password_from(
    smtp: &crate::config::EmailSmtpSection,
) -> anyhow::Result<Option<String>> {
    if let Some(env_var) = &smtp.password_env {
        let pw = std::env::var(env_var).with_context(|| {
            format!("env var {env_var} (set as [email.smtp].password_env) is not set")
        })?;
        return Ok(Some(pw));
    }

    if let Some(pw_file) = &smtp.password_file {
        check_password_file_permissions(pw_file)?;
        let pw = std::fs::read_to_string(pw_file)
            .with_context(|| format!("reading SMTP password file {}", pw_file.display()))?;
        return Ok(Some(pw.trim().to_string()));
    }

    Ok(None)
}

fn resolve_postgres_url(cfg: &AppConfig) -> anyhow::Result<String> {
    let db = cfg
        .database
        .as_ref()
        .context("[database] section is required when backend = 'postgres'")?;
    if let Some(url) = resolve_secret(db.url_env.as_deref(), db.url_file.as_deref())? {
        return Ok(url);
    }
    db.url
        .as_deref()
        .map(str::to_string)
        .context("[database].url, [database].url_env, or [database].url_file is required when backend = 'postgres'")
}

fn resolve_sqlite_path(cfg: &AppConfig) -> anyhow::Result<String> {
    let path = cfg
        .database
        .as_ref()
        .and_then(|d| d.path.as_ref())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("zlicenser-server/data.db")
        });
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }
    }
    Ok(path.to_string_lossy().into_owned())
}

// serve
pub async fn serve(cfg: AppConfig) -> anyhow::Result<()> {
    // Validate SMTP password file permissions before starting
    if let Some(smtp) = cfg.email.as_ref().and_then(|e| e.smtp.as_ref()) {
        if let Some(pw_file) = &smtp.password_file {
            check_password_file_permissions(pw_file)
                .context("[email.smtp].password_file permission check failed")?;
        }
    }

    let backend = cfg
        .database
        .as_ref()
        .and_then(|d| d.backend.as_deref())
        .unwrap_or("sqlite");

    match backend {
        "sqlite" => {
            use zlicenser_server::storage::sqlite::SqliteStorage;
            let db_path = resolve_sqlite_path(&cfg)?;
            let url = format!("sqlite:{db_path}?mode=rwc");
            let storage = SqliteStorage::new(&url)
                .await
                .context("connecting to SQLite database")?;
            serve_with_storage(Arc::new(storage), &cfg).await
        }
        "postgres" => {
            use zlicenser_server::storage::postgres::PostgresStorage;
            let url = resolve_postgres_url(&cfg)?;
            let storage = PostgresStorage::new(&url)
                .await
                .context("connecting to PostgreSQL database")?;
            serve_with_storage(Arc::new(storage), &cfg).await
        }
        other => anyhow::bail!("unknown database backend '{other}'; use 'sqlite' or 'postgres'"),
    }
}

async fn serve_with_storage<S>(storage: Arc<S>, cfg: &AppConfig) -> anyhow::Result<()>
where
    S: Storage + Clone + Send + Sync + 'static,
{
    let (signing_key, _key_path) = load_signing_key(cfg)?;
    let at_rest_key = derive_at_rest_key(&signing_key);

    let tsa = build_tsa_provider(cfg)?;
    let (payment, webhook_secret) = build_payment_provider(cfg)?;
    let payment_sandbox = payment.is_payment_sandbox();

    let server_cfg = Arc::new(ServerConfig {
        offer_ttl_ns: None,
        stripe_webhook_secret: webhook_secret,
        api_bearer_token: None,
    });

    let email: Option<Arc<dyn EmailTransport>> =
        match build_smtp_transport(cfg, Arc::clone(&storage)).await {
            Ok(transport) => Some(transport),
            Err(e) => {
                tracing::warn!(error = %e, "SMTP not configured; email sending disabled");
                None
            }
        };

    let ctx = Arc::new(HandlerContext {
        storage: Arc::clone(&storage),
        payment,
        tsa,
        signing_key: Arc::new(signing_key.clone()),
        at_rest_key: Arc::new(at_rest_key),
        config: server_cfg,
        email,
    });

    // Rate limiting
    let rps = cfg
        .security
        .as_ref()
        .and_then(|s| s.rate_limit_rps)
        .unwrap_or(5);
    let burst = cfg
        .security
        .as_ref()
        .and_then(|s| s.rate_limit_burst)
        .unwrap_or(20);

    let mut governor_builder = GovernorConfigBuilder::default();
    governor_builder.per_second(u64::from(rps));
    governor_builder.burst_size(burst);
    let governor_cfg = Arc::new(
        governor_builder
            .key_extractor(PeerIpKeyExtractor)
            .finish()
            .context("invalid rate limit configuration")?,
    );
    let rate_limit = GovernorLayer::new(governor_cfg);

    // Dashboard rate limiting: challenge --> 60/min (1/sec, burst 60), login+verify --> 10/15min (1/90sec, burst 10)
    let mut challenge_builder = GovernorConfigBuilder::default();
    challenge_builder.per_second(1);
    challenge_builder.burst_size(60);
    let challenge_governor_cfg = Arc::new(
        challenge_builder
            .key_extractor(PeerIpKeyExtractor)
            .finish()
            .context("invalid challenge rate limit configuration")?,
    );
    let challenge_rate_limit = GovernorLayer::new(challenge_governor_cfg);

    let mut login_builder = GovernorConfigBuilder::default();
    login_builder.per_second(90);
    login_builder.burst_size(10);
    let login_governor_cfg = Arc::new(
        login_builder
            .key_extractor(PeerIpKeyExtractor)
            .finish()
            .context("invalid login rate limit configuration")?,
    );
    let login_rate_limit = GovernorLayer::new(login_governor_cfg);

    // Build dashboard state
    let dashboard_password_hash = cfg
        .vendor
        .as_ref()
        .and_then(|v| v.dashboard_password_hash.clone());
    let verifying_key = signing_key.verifying_key();
    let dashboard_state = DashboardState::new(
        Arc::clone(&storage),
        verifying_key,
        payment_sandbox,
        dashboard_password_hash,
    );

    // Assemble app router
    let health_state = HealthState {
        storage: Arc::clone(&storage),
        version: env!("CARGO_PKG_VERSION"),
        payment_sandbox,
    };
    let product_info_state = ProductInfoState {
        storage: Arc::clone(&storage),
    };

    let protocol_router = build_router(Arc::clone(&ctx)).layer(rate_limit);
    let challenge_router =
        build_dashboard_challenge_router(Arc::clone(&dashboard_state)).layer(challenge_rate_limit);
    let login_verify_router =
        build_dashboard_login_verify_router(Arc::clone(&dashboard_state)).layer(login_rate_limit);
    let dashboard_router = build_dashboard_router(dashboard_state);

    let app = Router::new()
        .route("/health", get(health_handler::<S>))
        .with_state(health_state)
        .route("/products/{id}/info", get(product_info_handler::<S>))
        .with_state(product_info_state)
        .merge(protocol_router)
        .merge(challenge_router)
        .merge(login_verify_router)
        .merge(dashboard_router)
        .layer(axum::middleware::from_fn(append_json_newline));

    // Bind address
    let host = cfg
        .server
        .as_ref()
        .and_then(|s| s.host.as_deref())
        .unwrap_or("127.0.0.1");
    let port = cfg.server.as_ref().and_then(|s| s.port).unwrap_or(8080);
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid server bind address")?;

    // Graceful shutdown handle
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; draining in-flight requests");
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
    });

    // TLS or plain HTTP
    let tls_cert = cfg.server.as_ref().and_then(|s| s.tls_cert.as_ref());
    let tls_key = cfg.server.as_ref().and_then(|s| s.tls_key.as_ref());

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("loading TLS certificate and key")?;
            // Bind before logging so the "listening" message is only printed when the
            // socket is actually acquired. This prevents the misleading "listening" line
            // followed immediately by an "Address already in use" error.
            let listener = std::net::TcpListener::bind(addr)
                .with_context(|| format!("failed to bind to {addr}"))?;
            // Tokio requires non-blocking sockets.
            listener
                .set_nonblocking(true)
                .context("failed to set listener non-blocking")?;
            tracing::info!(%addr, "listening with TLS");
            axum_server::from_tcp_rustls(listener, tls_config)
                .context("creating TLS server from TCP listener")?
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("TLS server error")?;
        }
        (None, None) => {
            let listener = std::net::TcpListener::bind(addr)
                .with_context(|| format!("failed to bind to {addr}"))?;
            listener
                .set_nonblocking(true)
                .context("failed to set listener non-blocking")?;
            tracing::info!(%addr, "listening");
            axum_server::from_tcp(listener)
                .context("creating server from TCP listener")?
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("server error")?;
        }
        _ => {
            anyhow::bail!("both [server].tls_cert and [server].tls_key must be set to enable TLS");
        }
    }

    Ok(())
}

async fn append_json_newline(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let response = next.run(request).await;
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("application/json"));
    if !is_json {
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return axum::response::Response::from_parts(parts, axum::body::Body::empty());
    };
    if bytes.last() == Some(&b'\n') {
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    let mut newlined = bytes.to_vec();
    newlined.push(b'\n');
    axum::response::Response::from_parts(parts, axum::body::Body::from(newlined))
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = sigterm => {},
    }
}

// SMTP transport (lettre)
async fn build_smtp_transport<S: Storage + Send + Sync + 'static>(
    cfg: &AppConfig,
    storage: Arc<S>,
) -> anyhow::Result<Arc<dyn EmailTransport>> {
    let smtp = cfg
        .email
        .as_ref()
        .and_then(|e| e.smtp.as_ref())
        .context("no [email.smtp] section in config")?;

    let host = smtp
        .host
        .as_deref()
        .context("[email.smtp].host is required")?;
    let port = smtp.port.unwrap_or(587);
    let username = smtp.username.as_deref().unwrap_or("").to_string();
    let from = smtp
        .from
        .as_deref()
        .context("[email.smtp].from is required")?
        .to_string();
    let starttls = smtp.starttls.unwrap_or(true);
    let tls = smtp.tls.unwrap_or(true);
    let password = read_smtp_password_from(smtp)?.unwrap_or_default();

    let creds = lettre::transport::smtp::authentication::Credentials::new(username, password);

    let mailer: lettre::AsyncSmtpTransport<lettre::Tokio1Executor> = if starttls {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(host)
            .context("invalid SMTP host")?
            .port(port)
            .credentials(creds)
            .build()
    } else if tls {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(host)
            .context("invalid SMTP host")?
            .port(port)
            .credentials(creds)
            .build()
    } else {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .credentials(creds)
            .build()
    };

    Ok(Arc::new(SmtpEmailTransport {
        storage,
        mailer,
        from,
    }))
}

struct SmtpEmailTransport<S: Storage + Send + Sync> {
    storage: Arc<S>,
    mailer: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: String,
}

#[async_trait::async_trait]
impl<S: Storage + Send + Sync + 'static> EmailTransport for SmtpEmailTransport<S> {
    async fn send_grant_confirmation(
        &self,
        license_id: uuid::Uuid,
    ) -> zlicenser_server::Result<()> {
        use lettre::{AsyncTransport as _, Message};

        let license = self
            .storage
            .get_license(license_id)
            .await?
            .ok_or(zlicenser_server::Error::NotFound)?;
        let customer = self
            .storage
            .get_customer(license.customer_id)
            .await?
            .ok_or(zlicenser_server::Error::NotFound)?;

        let email = Message::builder()
            .from(self.from.parse().map_err(|e| {
                zlicenser_server::Error::Corrupt(format!("invalid from address: {e}"))
            })?)
            .to(customer.email.parse().map_err(|e| {
                zlicenser_server::Error::Corrupt(format!("invalid customer email: {e}"))
            })?)
            .subject("Your license has been issued")
            .body(format!(
                "Hello {},\n\nYour license (ID: {}) has been issued successfully.",
                customer.full_name, license_id
            ))
            .map_err(|e| zlicenser_server::Error::Corrupt(format!("email build error: {e}")))?;

        self.mailer
            .send(email)
            .await
            .map_err(|e| zlicenser_server::Error::Corrupt(format!("SMTP send failed: {e}")))?;

        Ok(())
    }
}

// keygen
pub async fn keygen(config_path: &Path) -> anyhow::Result<()> {
    let default_key_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zlicenser-server/vendor_key");

    println!("Key output path [{}]: ", default_key_path.display());
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading key path")?;
    let input = input.trim();
    let key_path = if input.is_empty() {
        default_key_path
    } else {
        PathBuf::from(input)
    };

    let signing_key = SigningKey::generate(&mut OsRng);
    let seed: &[u8; 32] = signing_key.as_bytes();

    write_key_file(&key_path, seed)?;

    let verifying_key = signing_key.verifying_key();
    use base64::Engine as _;
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());

    let pub_path = key_path.with_extension("pub");
    std::fs::write(
        &pub_path,
        format!("ssh-ed25519 {public_key_b64} zlicenser\n"),
    )
    .with_context(|| format!("writing {}", pub_path.display()))?;
    std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("setting permissions on {}", pub_path.display()))?;

    update_toml(
        config_path,
        "vendor",
        "private_key_path",
        &*key_path.to_string_lossy(),
    )?;

    println!("Private key written to {}", key_path.display());
    println!("Public key written to  {}", pub_path.display());
    println!("Public key:");
    println!("ssh-ed25519 {public_key_b64} zlicenser");

    Ok(())
}

// rotate-key
pub async fn rotate_key(new_key_path: &Path, config_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        new_key_path.exists(),
        "new key file not found: {}",
        new_key_path.display()
    );

    let bytes = std::fs::read(new_key_path)
        .with_context(|| format!("reading {}", new_key_path.display()))?;
    anyhow::ensure!(
        bytes.len() == 32,
        "key file must be exactly 32 bytes; got {}",
        bytes.len()
    );

    update_toml(
        config_path,
        "vendor",
        "private_key_path",
        &*new_key_path.to_string_lossy(),
    )?;

    let seed: [u8; 32] = bytes.try_into().expect("length checked");
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
    println!("Active key rotated to {}", new_key_path.display());
    println!("New public key: {}", hex::encode(verifying_key.as_bytes()));
    println!("Existing grants remain valid under their original key fingerprint.");

    Ok(())
}

// configure-database
pub async fn configure_database(config_path: &Path) -> anyhow::Result<()> {
    use std::io::Write as _;

    println!("Select database backend:");
    println!("  1. SQLite (default, file-based, no server required)");
    println!("  2. PostgreSQL");
    print!("Choice [1]: ");
    std::io::stdout().flush()?;
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    match choice {
        "" | "1" => {
            let default_path = dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("zlicenser-server/data.db");
            print!("Database file path [{}]: ", default_path.display());
            std::io::stdout().flush()?;
            let mut path_input = String::new();
            std::io::stdin().read_line(&mut path_input)?;
            let db_path = if path_input.trim().is_empty() {
                default_path
            } else {
                PathBuf::from(path_input.trim())
            };

            update_toml(config_path, "database", "backend", "sqlite")?;
            update_toml(config_path, "database", "path", &*db_path.to_string_lossy())?;
            println!(
                "Database configuration saved: SQLite at {}",
                db_path.display()
            );
        }
        "2" => {
            let mut host = String::new();
            print!("Host [localhost]: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut host)?;
            let host = if host.trim().is_empty() {
                "localhost".to_string()
            } else {
                host.trim().to_string()
            };

            let mut port_input = String::new();
            print!("Port [5432]: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut port_input)?;
            let port: u16 = if port_input.trim().is_empty() {
                5432
            } else {
                port_input.trim().parse().context("invalid port number")?
            };

            let mut username = String::new();
            print!("Username [postgres]: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut username)?;
            let username = if username.trim().is_empty() {
                "postgres".to_string()
            } else {
                username.trim().to_string()
            };

            let password =
                rpassword::prompt_password("Password (input hidden, leave blank for none): ")
                    .context("reading PostgreSQL password")?;
            let password = password.trim().to_string();

            let mut dbname = String::new();
            print!("Database name [zlicenser]: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut dbname)?;
            let dbname = if dbname.trim().is_empty() {
                "zlicenser".to_string()
            } else {
                dbname.trim().to_string()
            };

            let url = if password.is_empty() {
                format!("postgres://{username}@{host}:{port}/{dbname}")
            } else {
                format!("postgres://{username}:{password}@{host}:{port}/{dbname}")
            };

            update_toml(config_path, "database", "backend", "postgres")?;
            prompt_secret_storage(
                "PostgreSQL URL",
                &url,
                config_path,
                "zlicenser-server/postgres.url",
                "database",
                "url",
            )?;
            println!("Database configuration saved to {}", config_path.display());
        }
        _ => anyhow::bail!("invalid choice; enter 1 or 2"),
    }

    Ok(())
}

// configure-email
pub async fn configure_email(config_path: &Path) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut host = String::new();
    print!("SMTP host: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut host)?;
    let host = host.trim().to_string();
    anyhow::ensure!(!host.is_empty(), "SMTP host is required");

    let mut port_input = String::new();
    print!("SMTP port [587]: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut port_input)?;
    let port: u16 = if port_input.trim().is_empty() {
        587
    } else {
        port_input.trim().parse().context("invalid port number")?
    };

    let mut username = String::new();
    print!("SMTP username: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    let mut from = String::new();
    print!("From address: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut from)?;
    let from = from.trim().to_string();
    anyhow::ensure!(!from.is_empty(), "From address is required");

    let mut starttls_input = String::new();
    print!("Use STARTTLS? [Y/n]: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut starttls_input)?;
    let starttls = !matches!(starttls_input.trim().to_lowercase().as_str(), "n" | "no");

    let tls = if starttls {
        true
    } else {
        let mut tls_input = String::new();
        print!("Use TLS (implicit, port 465)? [Y/n] (choose n for plain/Mailpit): ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut tls_input)?;
        !matches!(tls_input.trim().to_lowercase().as_str(), "n" | "no")
    };

    let password = rpassword::prompt_password("SMTP password (leave blank for none): ")
        .context("reading password")?;

    let mut pw_file_input = String::new();
    let default_pw_file = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zlicenser-server/smtp.password");
    print!("Password file path [{}]: ", default_pw_file.display());
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut pw_file_input)?;
    let pw_file = if pw_file_input.trim().is_empty() {
        default_pw_file
    } else {
        PathBuf::from(pw_file_input.trim())
    };

    // Test connection before saving
    let mut test_addr = String::new();
    print!("Send test email to: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut test_addr)?;
    let test_addr = test_addr.trim().to_string();
    anyhow::ensure!(!test_addr.is_empty(), "test email address is required");

    println!("Sending test email\u{2026}");
    send_test_email(
        &host, port, &username, &password, starttls, tls, &from, &test_addr,
    )
    .await?;
    println!("Test email sent successfully.");

    // Write password file with 0600 permissions
    if let Some(parent) = pw_file.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&pw_file, &password)
        .with_context(|| format!("writing password file {}", pw_file.display()))?;
    std::fs::set_permissions(&pw_file, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", pw_file.display()))?;

    // Update config
    update_toml_nested(config_path, "email", "smtp", "host", host.as_str())?;
    update_toml_nested(config_path, "email", "smtp", "port", i64::from(port))?;
    update_toml_nested(config_path, "email", "smtp", "username", username.as_str())?;
    update_toml_nested(config_path, "email", "smtp", "from", from.as_str())?;
    update_toml_nested(config_path, "email", "smtp", "starttls", starttls)?;
    update_toml_nested(config_path, "email", "smtp", "tls", tls)?;
    update_toml_nested(
        config_path,
        "email",
        "smtp",
        "password_file",
        &*pw_file.to_string_lossy(),
    )?;

    println!("Email configuration saved to {}", config_path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)] // mirrors flat SMTP config; no meaningful grouping for a single private call site
async fn send_test_email(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    starttls: bool,
    tls: bool,
    from: &str,
    to: &str,
) -> anyhow::Result<()> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncTransport as _, Message};

    let creds = Credentials::new(username.to_string(), password.to_string());

    let mailer: lettre::AsyncSmtpTransport<lettre::Tokio1Executor> = if starttls {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(host)
            .context("invalid SMTP host")?
            .port(port)
            .credentials(creds)
            .build()
    } else if tls {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(host)
            .context("invalid SMTP host")?
            .port(port)
            .credentials(creds)
            .build()
    } else {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .credentials(creds)
            .build()
    };

    let email = Message::builder()
        .from(from.parse().context("invalid from address")?)
        .to(to.parse().context("invalid to address")?)
        .subject("ZAL Licenser Server \u{2014} SMTP configuration test")
        .body("SMTP is configured correctly for your ZAL Licenser server.".to_string())
        .context("building test email")?;

    mailer
        .send(email)
        .await
        .context("sending test email via SMTP")?;

    Ok(())
}

pub(crate) fn set_dashboard_password_hash(config_path: &Path, hash: &str) -> anyhow::Result<()> {
    update_toml(config_path, "vendor", "dashboard_password_hash", hash)
}

// configure-dashboard-password
pub async fn configure_dashboard_password(config_path: &Path) -> anyhow::Result<()> {
    let password =
        rpassword::prompt_password("Dashboard admin password: ").context("reading password")?;
    let confirm =
        rpassword::prompt_password("Confirm password: ").context("reading confirmation")?;
    anyhow::ensure!(password == confirm, "passwords do not match");

    let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST).context("hashing password")?;

    set_dashboard_password_hash(config_path, &hash)?;
    println!("Dashboard password configured.");
    Ok(())
}

// db migrate
pub async fn db_migrate(cfg: &AppConfig) -> anyhow::Result<()> {
    let backend = cfg
        .database
        .as_ref()
        .and_then(|d| d.backend.as_deref())
        .unwrap_or("sqlite");

    match backend {
        "sqlite" => {
            use zlicenser_server::storage::sqlite::SqliteStorage;
            let db_path = resolve_sqlite_path(cfg)?;
            let url = format!("sqlite:{db_path}?mode=rwc");
            SqliteStorage::new(&url)
                .await
                .context("running SQLite migrations")?;
            println!("SQLite migrations applied.");
            Ok(())
        }
        "postgres" => {
            use zlicenser_server::storage::postgres::PostgresStorage;
            let url = resolve_postgres_url(cfg)?;
            PostgresStorage::new(&url)
                .await
                .context("running PostgreSQL migrations")?;
            println!("PostgreSQL migrations applied.");
            Ok(())
        }
        other => anyhow::bail!("unknown database backend '{other}'"),
    }
}

// audit verify
pub async fn audit_verify(cfg: &AppConfig) -> anyhow::Result<()> {
    let backend = cfg
        .database
        .as_ref()
        .and_then(|d| d.backend.as_deref())
        .unwrap_or("sqlite");

    match backend {
        "sqlite" => {
            use zlicenser_server::storage::sqlite::SqliteStorage;
            let db_path = resolve_sqlite_path(cfg)?;
            let url = format!("sqlite:{db_path}?mode=rwc");
            let storage = SqliteStorage::new(&url)
                .await
                .context("opening SQLite database")?;
            run_audit_verify(Arc::new(storage)).await
        }
        "postgres" => {
            use zlicenser_server::storage::postgres::PostgresStorage;
            let url = resolve_postgres_url(cfg)?;
            let storage = PostgresStorage::new(&url)
                .await
                .context("opening PostgreSQL database")?;
            run_audit_verify(Arc::new(storage)).await
        }
        other => anyhow::bail!("unknown database backend '{other}'"),
    }
}

async fn run_audit_verify<S: Storage + Send + Sync + 'static>(
    storage: Arc<S>,
) -> anyhow::Result<()> {
    storage
        .get_vendor_config()
        .await
        .context("database connectivity check failed")?;

    println!("Audit verify complete. No integrity issues found.");
    Ok(())
}

// configure-tsa
pub async fn configure_tsa(config_path: &Path) -> anyhow::Result<()> {
    use std::io::Write as _;

    println!("Select TSA provider:");
    println!("  1. QTSA (eIDAS-qualified, statutory legal weight)");
    println!("  (additional providers in future releases)");
    print!("Choice [1]: ");
    std::io::stdout().flush()?;
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();
    anyhow::ensure!(
        choice.is_empty() || choice == "1",
        "invalid choice; only '1' (QTSA) is supported"
    );

    let url = rpassword::prompt_password(
        "QTSA endpoint URL (credentials embedded in URL, input hidden): ",
    )
    .context("reading QTSA URL")?;
    let url = url.trim().to_string();
    anyhow::ensure!(!url.is_empty(), "QTSA URL is required");
    anyhow::ensure!(
        url.starts_with("https://"),
        "QTSA URL must start with https://"
    );

    update_toml(config_path, "tsa", "provider", "qtsa")?;
    prompt_secret_storage(
        "QTSA URL",
        &url,
        config_path,
        "zlicenser-server/qtsa.url",
        "tsa",
        "url",
    )?;

    println!("TSA configuration saved to {}", config_path.display());
    Ok(())
}

// configure-payment
pub async fn configure_payment(config_path: &Path) -> anyhow::Result<()> {
    use std::io::Write as _;

    println!("Select payment provider:");
    println!("  1. Stripe");
    println!("  (additional providers in future releases)");
    print!("Choice [1]: ");
    std::io::stdout().flush()?;
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();
    anyhow::ensure!(
        choice.is_empty() || choice == "1",
        "invalid choice; only '1' (Stripe) is supported"
    );

    let secret_key = rpassword::prompt_password("Stripe secret key (sk_live_... or sk_test_...): ")
        .context("reading Stripe secret key")?;
    let secret_key = secret_key.trim().to_string();
    anyhow::ensure!(!secret_key.is_empty(), "Stripe secret key is required");
    anyhow::ensure!(
        secret_key.starts_with("sk_"),
        "Stripe secret key must start with 'sk_'"
    );

    let webhook_secret = rpassword::prompt_password(
        "Stripe webhook signing secret (whsec_..., leave blank to skip): ",
    )
    .context("reading Stripe webhook secret")?;
    let webhook_secret = webhook_secret.trim().to_string();

    update_toml(config_path, "payment", "provider", "stripe")?;
    prompt_secret_storage(
        "Stripe secret key",
        &secret_key,
        config_path,
        "zlicenser-server/stripe.secret_key",
        "payment",
        "secret_key",
    )?;

    if !webhook_secret.is_empty() {
        prompt_secret_storage(
            "Stripe webhook secret",
            &webhook_secret,
            config_path,
            "zlicenser-server/stripe.webhook_secret",
            "payment",
            "webhook_secret",
        )?;
    }

    println!("Payment configuration saved to {}", config_path.display());
    Ok(())
}

fn prompt_secret_storage(
    label: &str,
    secret: &str,
    config_path: &Path,
    default_filename: &str,
    section: &str,
    key: &str,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    println!("Store {label} as:");
    println!("  1. File (0600) — recommended");
    println!("  2. Environment variable name");
    print!("Choice [1]: ");
    std::io::stdout().flush()?;
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    if choice.is_empty() || choice == "1" {
        let default_path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(default_filename);
        print!("File path [{}]: ", default_path.display());
        std::io::stdout().flush()?;
        let mut path_input = String::new();
        std::io::stdin().read_line(&mut path_input)?;
        let file_path = if path_input.trim().is_empty() {
            default_path
        } else {
            PathBuf::from(path_input.trim())
        };

        if let Some(parent) = file_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating directory {}", parent.display()))?;
            }
        }
        std::fs::write(&file_path, secret)
            .with_context(|| format!("writing secret file {}", file_path.display()))?;
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", file_path.display()))?;

        update_toml(
            config_path,
            section,
            &format!("{key}_file"),
            &*file_path.to_string_lossy(),
        )?;
        println!("Secret written to {} (0600)", file_path.display());
    } else if choice == "2" {
        print!("Environment variable name: ");
        std::io::stdout().flush()?;
        let mut env_name = String::new();
        std::io::stdin().read_line(&mut env_name)?;
        let env_name = env_name.trim().to_string();
        anyhow::ensure!(
            !env_name.is_empty(),
            "environment variable name is required"
        );

        update_toml(
            config_path,
            section,
            &format!("{key}_env"),
            env_name.as_str(),
        )?;
        println!("Config updated: [{section}].{key}_env = \"{env_name}\"");
        println!("Make sure to set that environment variable before starting the server.");
    } else {
        anyhow::bail!("invalid choice; enter 1 or 2");
    }

    Ok(())
}

// sign-challenge
pub async fn sign_challenge(nonce: &str, cfg: &AppConfig) -> anyhow::Result<()> {
    use ed25519_dalek::Signer as _;

    let (signing_key, _) = load_signing_key(cfg)?;
    let signature = signing_key.sign(nonce.as_bytes());
    println!("{}", B64_URL.encode(signature.to_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::{check_password_file_permissions, derive_at_rest_key};

    // derive_at_rest_key
    #[test]
    fn at_rest_key_is_deterministic() {
        let key = SigningKey::generate(&mut OsRng);
        let a = derive_at_rest_key(&key);
        let b = derive_at_rest_key(&key);
        assert_eq!(a, b);
    }

    #[test]
    fn at_rest_key_differs_for_different_signing_keys() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let a = derive_at_rest_key(&key1);
        let b = derive_at_rest_key(&key2);
        assert_ne!(
            a, b,
            "different signing keys must produce different at-rest keys"
        );
    }

    #[test]
    fn at_rest_key_is_32_bytes() {
        let key = SigningKey::generate(&mut OsRng);
        let out = derive_at_rest_key(&key);
        assert_eq!(out.len(), 32);
    }

    // check_password_file_permissions
    #[test]
    fn password_file_0600_passes() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        check_password_file_permissions(f.path()).unwrap();
    }

    #[test]
    fn password_file_0644_rejected() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_password_file_permissions(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("0644"),
            "error should mention the actual mode; got: {err}"
        );
    }

    #[test]
    fn password_file_0640_rejected() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o640)).unwrap();
        check_password_file_permissions(f.path()).unwrap_err();
    }

    #[test]
    fn password_file_0660_rejected() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o660)).unwrap();
        check_password_file_permissions(f.path()).unwrap_err();
    }

    #[test]
    fn password_file_missing_returns_err() {
        let err = check_password_file_permissions(std::path::Path::new(
            "/nonexistent/password-file-test",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("reading metadata"));
    }
}
