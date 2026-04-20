//! OAuth 2.0 authorization-code provider: the endpoints a relying party
//! (yuxu-server) talks to. The browser-facing authorize flow is handled by
//! the SPA; this module exposes only the machine-facing pieces:
//!
//! - `POST /api/oauth/authorize` — the SPA calls this with the user's
//!   session JWT to mint a one-time code bound to that user + client.
//!   Returns the redirect URL the SPA should send the browser to.
//! - `POST /oauth/token` — relying party exchanges the code for an access
//!   token, authenticated via HTTP Basic (client_id / client_secret).
//! - `GET  /oauth/userinfo` — relying party reads the user profile using
//!   the access token.
//!
//! Authorization codes live in memory: they are short-lived and single-use,
//! so the trade-off of losing in-flight codes on restart is acceptable and
//! avoids a whole extra table and cleanup job.

use crate::{
    app_state::AppState,
    auth::{SESSION_AUDIENCE, UserProfile, bearer_token, find_user_by_id, issue_jwt, verify_jwt},
    config::ClientConfig,
    error::AppError,
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, header::AUTHORIZATION},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Audience claim for OAuth access tokens. Keeping this distinct from
/// `SESSION_AUDIENCE` prevents token-replay across the two surfaces even
/// though both are signed with the same symmetric key.
const ACCESS_TOKEN_AUDIENCE: &str = "oauth";

/// Single-shot authorization code plus the metadata needed to honor the
/// later token-exchange call. Creation time is tracked alongside the expiry
/// so an operator can tell stale entries from fresh ones in logs.
pub struct AuthCode {
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub expires_at: i64,
}

#[derive(Default)]
pub struct AuthCodeStore {
    inner: DashMap<String, AuthCode>,
}

impl AuthCodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new code. `code` is opaque to this store.
    pub fn insert(&self, code: String, entry: AuthCode) {
        self.inner.insert(code, entry);
    }

    /// Take the code out of the store (single-use). Returns None if the
    /// code is unknown. Callers are responsible for checking `expires_at`.
    pub fn take(&self, code: &str) -> Option<AuthCode> {
        self.inner.remove(code).map(|(_, v)| v)
    }

    /// Best-effort garbage collection. Called at the start of each token
    /// exchange so an idle service doesn't accumulate dead codes forever.
    pub fn gc(&self) {
        let now = Utc::now().timestamp();
        self.inner.retain(|_, entry| entry.expires_at > now);
    }
}

#[derive(Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub state: Option<String>,
    /// OAuth 2.0 expects this to always be `"code"`; we reject anything
    /// else so an implicit/token-response-type call can't sneak through.
    pub response_type: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub scope: Option<String>,
}

#[derive(Serialize)]
pub struct AuthorizeResponse {
    /// Where the SPA should redirect the browser next.
    pub redirect_url: String,
}

/// Mint an authorization code bound to the currently-logged-in user and the
/// requested client. The SPA supplies the user's session JWT in
/// `Authorization: Bearer <...>`; we never trust query-parameter identity
/// here even though the same info reaches us via the URL.
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, AppError> {
    if req.response_type != "code" {
        return Err(AppError::BadRequest(
            "unsupported_response_type; only \"code\" is allowed".into(),
        ));
    }
    let session_token = bearer_token(&headers).ok_or_else(|| {
        AppError::Unauthorized("must be signed in to authorize an OAuth request".into())
    })?;
    let claims = verify_jwt(
        state.config.jwt_secret.as_bytes(),
        &session_token,
        SESSION_AUDIENCE,
    )?;
    let client = state
        .config
        .find_client(&req.client_id)
        .ok_or_else(|| AppError::Unauthorized("unknown client_id".into()))?;
    ensure_redirect_uri_allowed(client, &req.redirect_uri)?;

    // `sub` is the Zixiao Cloud user id; the client receives it as `sub`
    // in the userinfo response and stores it as `zixiao_cloud_id` locally.
    let code = random_opaque_token(32);
    let now = Utc::now().timestamp();
    state.codes.insert(
        code.clone(),
        AuthCode {
            user_id: claims.sub,
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            expires_at: now + state.config.code_ttl_secs,
        },
    );

    let mut url = url::Url::parse(&req.redirect_uri)
        .map_err(|_| AppError::BadRequest("redirect_uri is not a valid URL".into()))?;
    url.query_pairs_mut().append_pair("code", &code);
    if let Some(s) = req.state.as_deref() {
        url.query_pairs_mut().append_pair("state", s);
    }

    Ok(Json(AuthorizeResponse {
        redirect_url: url.into(),
    }))
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Only accepted when the client didn't authenticate via HTTP Basic.
    /// Belt-and-suspenders: we prefer Basic and validate it when present.
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

/// Standard OAuth token exchange. Accepts client credentials via either
/// HTTP Basic auth (preferred) or `client_id` + `client_secret` in the form
/// body, matching what most OAuth client libraries send.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    if req.grant_type != "authorization_code" {
        return Err(AppError::BadRequest(
            "unsupported_grant_type; only authorization_code is allowed".into(),
        ));
    }

    let (basic_id, basic_secret) = parse_basic_auth(&headers);
    let client_id = basic_id
        .as_deref()
        .or(req.client_id.as_deref())
        .ok_or_else(|| AppError::Unauthorized("missing client credentials".into()))?;
    let provided_secret = basic_secret
        .as_deref()
        .or(req.client_secret.as_deref())
        .ok_or_else(|| AppError::Unauthorized("missing client credentials".into()))?;

    let client = state
        .config
        .find_client(client_id)
        .ok_or_else(|| AppError::Unauthorized("unknown client_id".into()))?;
    if !constant_time_eq(client.client_secret.as_bytes(), provided_secret.as_bytes()) {
        return Err(AppError::Unauthorized("invalid client credentials".into()));
    }

    state.codes.gc();
    let entry = state.codes.take(&req.code).ok_or_else(|| {
        AppError::BadRequest("invalid_grant: code unknown or already used".into())
    })?;
    if entry.expires_at <= Utc::now().timestamp() {
        return Err(AppError::BadRequest("invalid_grant: code expired".into()));
    }
    // The code was minted for exactly one client+redirect pair. Rebinding
    // it to a different client later would hand the relying party a code
    // that was issued against someone else's consent; rebinding the
    // redirect URI would let a malicious site collect the code.
    if entry.client_id != client_id {
        return Err(AppError::BadRequest(
            "invalid_grant: code issued to a different client".into(),
        ));
    }
    if entry.redirect_uri != req.redirect_uri {
        return Err(AppError::BadRequest(
            "invalid_grant: redirect_uri does not match the authorize request".into(),
        ));
    }

    let access_token = issue_jwt(
        state.config.jwt_secret.as_bytes(),
        &entry.user_id,
        state.config.access_token_ttl_secs,
        ACCESS_TOKEN_AUDIENCE,
    )?;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.access_token_ttl_secs,
    }))
}

/// Resolve an access token to the user profile the relying party needs to
/// create/update its local record. `sub` is the stable identifier the
/// client uses to key future logins.
pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, AppError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| AppError::Unauthorized("missing bearer access token".into()))?;
    let claims = verify_jwt(
        state.config.jwt_secret.as_bytes(),
        &token,
        ACCESS_TOKEN_AUDIENCE,
    )?;
    let user = find_user_by_id(&state.db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::Unauthorized("account no longer exists".into()))?;
    let profile: UserProfile = user.to_profile();
    Ok(Json(UserInfoResponse {
        sub: profile.id,
        username: profile.username,
        email: profile.email,
        name: profile.display_name,
        avatar_url: profile.avatar_url,
        bio: profile.bio,
    }))
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub username: String,
    pub email: String,
    pub name: String,
    pub avatar_url: String,
    pub bio: String,
}

fn ensure_redirect_uri_allowed(client: &ClientConfig, redirect_uri: &str) -> Result<(), AppError> {
    // Parsing catches silly cases (missing scheme) before the prefix check
    // has a chance to accept a URL the browser would never actually load.
    if url::Url::parse(redirect_uri).is_err() {
        return Err(AppError::BadRequest(
            "redirect_uri is not a valid URL".into(),
        ));
    }
    if !redirect_uri.starts_with(&client.redirect_uri_prefix) {
        return Err(AppError::BadRequest(
            "redirect_uri is not allowed for this client".into(),
        ));
    }
    Ok(())
}

fn parse_basic_auth(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let Some(hv) = headers.get(AUTHORIZATION) else {
        return (None, None);
    };
    let Ok(s) = hv.to_str() else {
        return (None, None);
    };
    let Some(rest) = s
        .strip_prefix("Basic ")
        .or_else(|| s.strip_prefix("basic "))
    else {
        return (None, None);
    };
    let Ok(decoded) = general_purpose::STANDARD.decode(rest.trim()) else {
        return (None, None);
    };
    let Ok(as_str) = std::str::from_utf8(&decoded) else {
        return (None, None);
    };
    // Clients are allowed to URL-encode the two components per RFC 6749
    // section 2.3.1 before joining them with `:`. jsonwebtoken + reqwest's
    // basic_auth don't bother; neither do we — most callers will match.
    match as_str.split_once(':') {
        Some((id, secret)) => (Some(id.to_string()), Some(secret.to_string())),
        None => (None, None),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn random_opaque_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equality_on_equal_length_inputs() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn redirect_uri_prefix_check_rejects_mismatches() {
        let client = ClientConfig {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri_prefix: "http://localhost:8080/".into(),
        };
        assert!(
            ensure_redirect_uri_allowed(&client, "http://localhost:8080/oauth/callback").is_ok()
        );
        // Different port, different host — both must fail.
        assert!(
            ensure_redirect_uri_allowed(&client, "http://localhost:9999/oauth/callback").is_err()
        );
        assert!(
            ensure_redirect_uri_allowed(&client, "http://evil.example/oauth/callback").is_err()
        );
        // Non-URL input bails at parse().
        assert!(ensure_redirect_uri_allowed(&client, "not a url").is_err());
    }

    #[test]
    fn parse_basic_auth_handles_common_shapes() {
        let mut headers = HeaderMap::new();
        let encoded = general_purpose::STANDARD.encode(b"cid:secret");
        headers.insert(AUTHORIZATION, format!("Basic {encoded}").parse().unwrap());
        let (id, secret) = parse_basic_auth(&headers);
        assert_eq!(id.as_deref(), Some("cid"));
        assert_eq!(secret.as_deref(), Some("secret"));

        let mut empty = HeaderMap::new();
        assert_eq!(parse_basic_auth(&empty), (None, None));

        empty.insert(AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert_eq!(parse_basic_auth(&empty), (None, None));
    }

    #[test]
    fn auth_code_store_is_single_use() {
        let store = AuthCodeStore::new();
        store.insert(
            "c".into(),
            AuthCode {
                user_id: "u".into(),
                client_id: "cid".into(),
                redirect_uri: "http://x/".into(),
                expires_at: i64::MAX,
            },
        );
        assert!(store.take("c").is_some());
        assert!(store.take("c").is_none());
    }
}
