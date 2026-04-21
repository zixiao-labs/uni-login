//! Env-driven config. Mirrors the shape of yuxu-server's `config.rs` so
//! operators can move between them without surprise.

use anyhow::{Context, Result, bail};
use std::net::SocketAddr;

/// One registered OAuth client. We validate `redirect_uri` sent by a relying
/// party against `redirect_uri_prefix` using a literal starts-with check.
/// This is deliberately strict: a mis-configured wildcard here would let any
/// site receive authorization codes minted for this client.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri_prefix: String,
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub jwt_secret: String,
    pub session_ttl_secs: i64,
    pub access_token_ttl_secs: i64,
    pub code_ttl_secs: i64,
    pub clients: Vec<ClientConfig>,
    pub cors_allowed_origins: Option<String>,
}

impl std::fmt::Debug for Config {
    /// Formats `Config` for debug output while redacting sensitive fields.
    ///
    /// This `Debug` formatter prints a structured representation of the `Config`
    /// but replaces sensitive values with `"<redacted>"`: the `database_url`,
    /// `jwt_secret`, and each `ClientConfig`'s `client_secret` are not shown.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::SocketAddr;
    /// let cfg = crate::Config {
    ///     bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
    ///     database_url: "postgres://user:password@localhost/db".into(),
    ///     jwt_secret: "supersecretsecretthatislongenough".into(),
    ///     session_ttl_secs: 3600,
    ///     access_token_ttl_secs: 3600,
    ///     code_ttl_secs: 120,
    ///     clients: vec![crate::ClientConfig {
    ///         client_id: "cid".into(),
    ///         client_secret: "client-secret".into(),
    ///         redirect_uri_prefix: "https://example.com/".into(),
    ///     }],
    ///     cors_allowed_origins: None,
    /// };
    ///
    /// let s = format!("{cfg:?}");
    /// assert!(s.contains("\"database_url\": \"<redacted>\""));
    /// assert!(s.contains("\"jwt_secret\": \"<redacted>\""));
    /// assert!(s.contains("client_secret: <redacted>"));
    /// assert!(s.contains("cid"));
    /// assert!(s.contains("https://example.com/"));
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't render jwt_secret, per-client secrets, or the database URL
        // (which may embed a password).
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("database_url", &"<redacted>")
            .field("jwt_secret", &"<redacted>")
            .field("session_ttl_secs", &self.session_ttl_secs)
            .field("access_token_ttl_secs", &self.access_token_ttl_secs)
            .field("code_ttl_secs", &self.code_ttl_secs)
            .field(
                "clients",
                &self
                    .clients
                    .iter()
                    .map(|c| {
                        format!(
                            "ClientConfig {{ client_id: {:?}, client_secret: <redacted>, redirect_uri_prefix: {:?} }}",
                            c.client_id, c.redirect_uri_prefix
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .finish()
    }
}

/// Reads an environment variable, trims leading and trailing whitespace, and returns `None` if the variable is not set or the trimmed value is empty.
///
/// # Examples
///
/// ```
/// std::env::remove_var("FOO");
/// assert_eq!(env_nonempty_trimmed("FOO"), None);
///
/// std::env::set_var("FOO", "  value  ");
/// assert_eq!(env_nonempty_trimmed("FOO"), Some("value".to_string()));
///
/// std::env::set_var("FOO", "   ");
/// assert_eq!(env_nonempty_trimmed("FOO"), None);
/// ```
fn env_nonempty_trimmed(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

impl Config {
    /// Builds a `Config` by reading and validating required environment variables.
    ///
    /// Reads configuration from environment variables, applying sensible defaults where documented,
    /// enforces a minimum JWT secret length, parses positive integer TTLs, parses and validates
    /// the `ZXCLOUD_CLIENTS` list (format: `id,secret,redirect_uri_prefix;...`), and returns a
    /// fully populated `Config` or an error if any required value is missing or invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `ZXCLOUD_BIND` is present but not a valid `SocketAddr`,
    /// - `ZXCLOUD_JWT_SECRET` is missing or shorter than 32 bytes,
    /// - any TTL environment variable is present but not a positive integer,
    /// - any `ZXCLOUD_CLIENTS` entry is malformed (wrong field count, empty fields),
    /// - any client's `redirect_uri_prefix` is not a valid URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::env;
    /// // Minimal required env vars for demonstration
    /// env::set_var("ZXCLOUD_JWT_SECRET", "a".repeat(32));
    /// // Optional: override bind to a deterministic value for the example
    /// env::set_var("ZXCLOUD_BIND", "127.0.0.1:5180");
    ///
    /// let cfg = server::config::Config::from_env().unwrap();
    /// assert_eq!(cfg.bind.ip().to_string(), "127.0.0.1");
    /// ```
    pub fn from_env() -> Result<Self> {
        let bind_raw = std::env::var("ZXCLOUD_BIND").unwrap_or_else(|_| "0.0.0.0:5180".into());
        let bind: SocketAddr = bind_raw
            .parse()
            .with_context(|| format!("ZXCLOUD_BIND is not a valid SocketAddr: {bind_raw}"))?;

        let database_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://zxcloud.db?mode=rwc".into());

        let jwt_secret = match std::env::var("ZXCLOUD_JWT_SECRET") {
            Ok(s) if s.len() >= 32 => s,
            Ok(_) => bail!("ZXCLOUD_JWT_SECRET must be at least 32 bytes"),
            Err(_) => bail!("ZXCLOUD_JWT_SECRET is required (>=32 bytes)"),
        };

        let session_ttl_secs = parse_positive_env("ZXCLOUD_SESSION_TTL_SECS", 60 * 60 * 24)?;
        let access_token_ttl_secs = parse_positive_env("ZXCLOUD_ACCESS_TOKEN_TTL_SECS", 60 * 60)?;
        let code_ttl_secs = parse_positive_env("ZXCLOUD_CODE_TTL_SECS", 120)?;

        // Parse `ZXCLOUD_CLIENTS` as `id,secret,prefix;id,secret,prefix;...`.
        // Empty is allowed (the SPA's local login still works), but any OAuth
        // relying party will get rejected at /oauth/authorize until at least
        // one client is configured.
        let raw_clients = env_nonempty_trimmed("ZXCLOUD_CLIENTS").unwrap_or_default();
        let mut clients = Vec::new();
        for (idx, entry) in raw_clients.split(';').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let parts: Vec<&str> = entry.split(',').map(str::trim).collect();
            if parts.len() != 3 {
                bail!(
                    "ZXCLOUD_CLIENTS entry #{idx} must have 3 comma-separated fields: id,secret,redirect_uri_prefix"
                );
            }
            if parts.iter().any(|p| p.is_empty()) {
                bail!("ZXCLOUD_CLIENTS entry #{idx} has empty fields");
            }
            // A prefix that doesn't look like a URL is almost certainly a
            // misconfiguration (users forgetting the scheme etc.) — surface
            // it at startup rather than on the first failed authorize.
            if url::Url::parse(parts[2]).is_err() {
                bail!(
                    "ZXCLOUD_CLIENTS entry #{idx}: redirect_uri_prefix {:?} is not a valid URL",
                    parts[2]
                );
            }
            clients.push(ClientConfig {
                client_id: parts[0].to_string(),
                client_secret: parts[1].to_string(),
                redirect_uri_prefix: parts[2].to_string(),
            });
        }

        Ok(Self {
            bind,
            database_url,
            jwt_secret,
            session_ttl_secs,
            access_token_ttl_secs,
            code_ttl_secs,
            clients,
            cors_allowed_origins: env_nonempty_trimmed("ZXCLOUD_CORS_ORIGINS"),
        })
    }

    /// Finds a registered OAuth client by its client identifier.
    ///
    —
    /// Returns `Some(&ClientConfig)` when a client with the given id exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::SocketAddr;
    /// let client = ClientConfig {
    ///     client_id: "app".into(),
    ///     client_secret: "secret".into(),
    ///     redirect_uri_prefix: "https://example.com/".into(),
    /// };
    /// let cfg = Config {
    ///     bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
    ///     database_url: "sqlite://:memory:".into(),
    ///     jwt_secret: "a".repeat(32),
    ///     session_ttl_secs: 86400,
    ///     access_token_ttl_secs: 3600,
    ///     code_ttl_secs: 120,
    ///     clients: vec![client.clone()],
    ///     cors_allowed_origins: None,
    /// };
    /// assert!(cfg.find_client("app").is_some());
    /// assert!(cfg.find_client("missing").is_none());
    /// ```
    pub fn find_client(&self, client_id: &str) -> Option<&ClientConfig> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }
}

/// Read an environment variable and parse it as a positive integer, falling back to a default if unset.
///
/// On success, returns the parsed integer when the environment variable is present and greater than zero;
/// returns `default` when the environment variable is not set. If the variable is present but cannot be
/// parsed as a positive integer, returns an error with context containing the environment key and value.
///
/// # Examples
///
/// ```
/// use anyhow::Result;
///
/// // ensure no env var is set
/// std::env::remove_var("TEST_POSITIVE_TTL");
/// assert_eq!(super::parse_positive_env("TEST_POSITIVE_TTL", 42).unwrap(), 42);
///
/// // valid positive value
/// std::env::set_var("TEST_POSITIVE_TTL", "10");
/// assert_eq!(super::parse_positive_env("TEST_POSITIVE_TTL", 42).unwrap(), 10);
///
/// // invalid or non-positive values produce an error
/// std::env::set_var("TEST_POSITIVE_TTL", "0");
/// assert!(super::parse_positive_env("TEST_POSITIVE_TTL", 42).is_err());
/// ```
fn parse_positive_env(key: &str, default: i64) -> Result<i64> {
    match std::env::var(key) {
        Ok(v) => {
            let n: i64 = v
                .parse()
                .with_context(|| format!("{key} must be a positive integer: {v}"))?;
            if n <= 0 {
                bail!("{key} must be positive");
            }
            Ok(n)
        }
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that the `Debug` implementation for `Config` redacts sensitive values while still showing non-sensitive fields.
    ///
    /// The test checks that `jwt_secret`, `database_url` (sensitive path/password), and each client's `client_secret` are omitted from the formatted debug output, and that `client_id` and `redirect_uri_prefix` remain present.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = Config {
    ///     bind: "127.0.0.1:5180".parse().unwrap(),
    ///     database_url: "sqlite:///secret-path/zxcloud.db?password=pw".into(),
    ///     jwt_secret: "x".repeat(48),
    ///     session_ttl_secs: 3600,
    ///     access_token_ttl_secs: 3600,
    ///     code_ttl_secs: 60,
    ///     clients: vec![ClientConfig {
    ///         client_id: "yuxu".into(),
    ///         client_secret: "oauth-secret".into(),
    ///         redirect_uri_prefix: "http://localhost:8080/".into(),
    ///     }],
    ///     cors_allowed_origins: None,
    /// };
    /// let rendered = format!("{cfg:?}");
    /// assert!(!rendered.contains("oauth-secret"));
    /// assert!(!rendered.contains(&"x".repeat(48)));
    /// assert!(!rendered.contains("/secret-path/"));
    /// assert!(rendered.contains("yuxu"));
    /// assert!(rendered.contains("http://localhost:8080/"));
    /// ```
    #[test]
    fn debug_impl_redacts_secrets() {
        let cfg = Config {
            bind: "127.0.0.1:5180".parse().unwrap(),
            database_url: "sqlite:///secret-path/zxcloud.db?password=pw".into(),
            jwt_secret: "x".repeat(48),
            session_ttl_secs: 3600,
            access_token_ttl_secs: 3600,
            code_ttl_secs: 60,
            clients: vec![ClientConfig {
                client_id: "yuxu".into(),
                client_secret: "oauth-secret".into(),
                redirect_uri_prefix: "http://localhost:8080/".into(),
            }],
            cors_allowed_origins: None,
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("oauth-secret"));
        assert!(!rendered.contains(&"x".repeat(48)));
        assert!(!rendered.contains("/secret-path/"));
        assert!(rendered.contains("yuxu"));
        assert!(rendered.contains("http://localhost:8080/"));
    }
}
