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

    /// Look up a registered client by id. `None` if not present — callers
    /// should map that to a 401/404 so the caller can't enumerate valid ids.
    pub fn find_client(&self, client_id: &str) -> Option<&ClientConfig> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }
}

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
