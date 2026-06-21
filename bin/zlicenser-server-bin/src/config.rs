use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct ServerSection {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DatabaseSection {
    pub backend: Option<String>,
    pub path: Option<PathBuf>,
    pub url: Option<String>,
    pub url_env: Option<String>,
    pub url_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct VendorSection {
    pub private_key_path: Option<PathBuf>,
    pub dashboard_password_hash: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct EmailSmtpSection {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub from: Option<String>,
    pub starttls: Option<bool>,
    /// Set to false for plain/unencrypted connections (e.g. Mailpit on port 1025).
    /// Defaults to true. Ignored when starttls = true.
    pub tls: Option<bool>,
    pub password_env: Option<String>,
    pub password_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct EmailSection {
    pub smtp: Option<EmailSmtpSection>,
}

#[derive(Debug, Deserialize, Default)]
pub struct LogSection {
    pub level: Option<String>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SecuritySection {
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TsaSection {
    pub provider: Option<String>,
    /// Name of the environment variable holding the TSA endpoint URL (with embedded credentials).
    pub url_env: Option<String>,
    /// Path to a 0600 file holding the TSA endpoint URL.
    pub url_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PaymentSection {
    pub provider: Option<String>,
    /// Name of the environment variable holding the Stripe secret key.
    pub secret_key_env: Option<String>,
    /// Path to a 0600 file holding the Stripe secret key.
    pub secret_key_file: Option<PathBuf>,
    /// Name of the environment variable holding the Stripe webhook signing secret.
    pub webhook_secret_env: Option<String>,
    /// Path to a 0600 file holding the Stripe webhook signing secret.
    pub webhook_secret_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AppConfig {
    pub server: Option<ServerSection>,
    pub database: Option<DatabaseSection>,
    pub vendor: Option<VendorSection>,
    pub email: Option<EmailSection>,
    pub log: Option<LogSection>,
    pub security: Option<SecuritySection>,
    pub tsa: Option<TsaSection>,
    pub payment: Option<PaymentSection>,
}

/// Resolves a secret from either an env var name or a 0600 file path.
pub fn resolve_secret(
    env_var: Option<&str>,
    file: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    if let Some(var) = env_var {
        let val = std::env::var(var)
            .with_context(|| format!("env var `{var}` (referenced in config) is not set"))?;
        return Ok(Some(val));
    }
    if let Some(path) = file {
        check_secret_file_permissions(path)?;
        let val = std::fs::read_to_string(path)
            .with_context(|| format!("reading secret file {}", path.display()))?;
        return Ok(Some(val.trim().to_string()));
    }
    Ok(None)
}

fn check_secret_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    let mode = meta.permissions().mode();
    anyhow::ensure!(
        mode & 0o177 == 0,
        "secret file {} has permissions {:04o}; must be exactly 0600",
        path.display(),
        mode & 0o777
    );
    Ok(())
}

/// Loads config from the given path, or searches standard locations.
/// Returns the parsed config and the resolved path used.
pub fn load_config(config_path: Option<PathBuf>) -> anyhow::Result<(AppConfig, PathBuf)> {
    let path = config_path.unwrap_or_else(find_config_file);

    if !path.exists() {
        return Ok((AppConfig::default(), path));
    }

    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config file at {}", path.display()))?;

    let cfg: AppConfig = toml::from_str(&content)
        .with_context(|| format!("parsing config file at {}", path.display()))?;

    Ok((cfg, path))
}

fn find_config_file() -> PathBuf {
    let candidates = [
        PathBuf::from("./zlicenser-server.toml"),
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("zlicenser-server/config.toml"),
        PathBuf::from("/etc/zlicenser-server/config.toml"),
    ];

    candidates
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("~/.config"))
                .join("zlicenser-server/config.toml")
        })
}

/// Updates a single key in a TOML config file, creating the file and section if needed.
pub fn update_toml(
    path: &Path,
    section: &str,
    key: &str,
    val: impl Into<toml_edit::Value>,
) -> anyhow::Result<()> {
    let content = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;

    if doc.get(section).is_none() {
        doc[section] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc[section][key] = toml_edit::value(val.into());

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    std::fs::write(path, doc.to_string()).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

/// Updates a key nested under `[section.subsection]`.
pub fn update_toml_nested(
    path: &Path,
    section: &str,
    subsection: &str,
    key: &str,
    val: impl Into<toml_edit::Value>,
) -> anyhow::Result<()> {
    let content = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;

    if doc.get(section).is_none() {
        doc[section] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if doc[section].get(subsection).is_none() {
        doc[section][subsection] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc[section][subsection][key] = toml_edit::value(val.into());

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }
    std::fs::write(path, doc.to_string()).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;

    use super::load_config;

    #[test]
    fn missing_file_returns_default() {
        let path = PathBuf::from("/nonexistent/zlicenser-server-test-config-absent.toml");
        let (cfg, _) = load_config(Some(path)).unwrap();
        assert!(cfg.server.is_none());
        assert!(cfg.database.is_none());
        assert!(cfg.vendor.is_none());
    }

    #[test]
    fn valid_toml_parses_all_sections() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[server]
host = "127.0.0.1"
port = 9000

[database]
backend = "sqlite"
path = "/tmp/test.db"

[log]
level = "debug"
format = "json"

[security]
rate_limit_rps = 10
rate_limit_burst = 20
"#
        )
        .unwrap();
        let (cfg, _) = load_config(Some(f.path().to_path_buf())).unwrap();
        let server = cfg.server.unwrap();
        assert_eq!(server.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(server.port, Some(9000));
        let db = cfg.database.unwrap();
        assert_eq!(db.backend.as_deref(), Some("sqlite"));
        let log = cfg.log.unwrap();
        assert_eq!(log.level.as_deref(), Some("debug"));
        let sec = cfg.security.unwrap();
        assert_eq!(sec.rate_limit_rps, Some(10));
        assert_eq!(sec.rate_limit_burst, Some(20));
    }

    #[test]
    fn invalid_toml_returns_err_with_path_in_message() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "[[not_valid_toml = oops").unwrap();
        let err = load_config(Some(f.path().to_path_buf())).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(f.path().to_str().unwrap()),
            "error should mention the config file path; got: {msg}"
        );
    }
}
