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
    /// Creates a new, empty AuthCodeStore.
    ///
    /// # Examples
    ///
    /// ```
    /// let store = AuthCodeStore::new();
    /// // store can be used to insert and take authorization codes
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores an authorization code and its associated metadata in the in-memory store,
    /// replacing any existing entry for the same code.
    ///
    /// # Examples
    ///
    /// ```
    /// let store = AuthCodeStore::new();
    /// let code = "abc123".to_string();
    /// let entry = AuthCode {
    ///     user_id: "user1".into(),
    ///     client_id: "client1".into(),
    ///     redirect_uri: "https://example.com/cb".into(),
    ///     expires_at: 1_000_000_000,
    /// };
    /// store.insert(code.clone(), entry);
    /// assert!(store.take(&code).is_some());
    /// ```
    pub fn insert(&self, code: String, entry: AuthCode) {
        self.inner.insert(code, entry);
    }

    /// Removes and returns a stored authorization code entry for single-use.
    ///
    /// Callers must verify the returned entry's `expires_at` timestamp before trusting it.
    ///
    /// # Examples
    ///
    /// ```
    /// let store = AuthCodeStore::new();
    /// let code = "c1".to_string();
    /// let entry = AuthCode {
    ///     user_id: "u".into(),
    ///     client_id: "cid".into(),
    ///     redirect_uri: "https://example.com/cb".into(),
    ///     expires_at: 1_000_000_000,
    /// };
    /// store.insert(code.clone(), entry);
    /// let taken = store.take(&code);
    /// assert!(taken.is_some());
    /// // subsequent takes return None (single-use)
    /// assert!(store.take(&code).is_none());
    /// ```
    pub fn take(&self, code: &str) -> Option<AuthCode> {
        self.inner.remove(code).map(|(_, v)| v)
    }

    /// Removes expired authorization codes from the in-memory store.
    ///
    /// This performs a best-effort sweep using the current UTC time and discards
    /// entries whose `expires_at` is less than or equal to now.
    ///
    /// # Examples
    ///
    /// ```
    /// let store = AuthCodeStore::new();
    /// let now = chrono::Utc::now().timestamp();
    /// store.insert(
    ///     "expired".into(),
    ///     AuthCode {
    ///         user_id: "user".into(),
    ///         client_id: "client".into(),
    ///         redirect_uri: "https://example.com/cb".into(),
    ///         expires_at: now - 1,
    ///     },
    /// );
    /// store.insert(
    ///     "valid".into(),
    ///     AuthCode {
    ///         user_id: "user".into(),
    ///         client_id: "client".into(),
    ///         redirect_uri: "https://example.com/cb".into(),
    ///         expires_at: now + 3600,
    ///     },
    /// );
    /// store.gc();
    /// assert!(store.take("expired").is_none());
    /// assert!(store.take("valid").is_some());
    /// ```
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

/// Validate an OAuth authorization request without minting an authorization code.
///
/// Performs the same client and redirect URI validation as `authorize`, but does not
/// create or store an `AuthCode` entry. Returns only the validated `redirect_url`.
/// Used by the frontend to safely construct error redirects when the user denies consent.
///
/// # Errors
///
/// Returns `AppError::BadRequest` for invalid `response_type` or malformed
/// `redirect_uri`, and `AppError::Unauthorized` for missing/invalid session
/// token or unknown client. Other JWT verification failures are propagated.
pub async fn authorize_validate(
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
    verify_jwt(
        state.config.jwt_secret.as_bytes(),
        &session_token,
        SESSION_AUDIENCE,
    )?;
    let client = state
        .config
        .find_client(&req.client_id)
        .ok_or_else(|| AppError::Unauthorized("unknown client_id".into()))?;
    ensure_redirect_uri_allowed(client, &req.redirect_uri)?;

    // Return the validated redirect_uri without minting a code
    let mut url = url::Url::parse(&req.redirect_uri)
        .map_err(|_| AppError::BadRequest("redirect_uri is not a valid URL".into()))?;

    // Don't add code parameter, just return the base URL for the caller to add error params
    if let Some(s) = req.state.as_deref() {
        url.query_pairs_mut().append_pair("state", s);
    }

    Ok(Json(AuthorizeResponse {
        redirect_url: url.into(),
    }))
}

/// Mint an authorization code for the authenticated user and return a redirect URL
/// that includes the code (and the original `state` if provided).
///
/// Validates that `response_type` is `"code"`, requires a session bearer token,
/// verifies the session JWT, ensures the client exists and the `redirect_uri`
/// is allowed for that client, and stores a single-use code bound to the
/// user, client, and redirect URI with a configured TTL. The returned redirect
/// URL is the parsed `redirect_uri` with `code=<minted code>` and optional
/// `state=<state>` query parameters appended.
///
/// # Errors
///
/// Returns `AppError::BadRequest` for invalid `response_type` or malformed
/// `redirect_uri`, and `AppError::Unauthorized` for missing/invalid session
/// token or unknown client. Other JWT verification failures are propagated.
///
/// # Examples
///
/// ```
/// // This example illustrates the shape of the redirect URL produced:
/// let redirect_uri = "https://example.com/callback";
/// let code = "opaque_code_123";
/// let url = url::Url::parse(redirect_uri).unwrap();
/// let mut url = url::Url::parse(redirect_uri).unwrap();
/// url.query_pairs_mut().append_pair("code", code);
/// assert!(url.as_str().contains("code=opaque_code_123"));
/// ```
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
    state.codes.gc();
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

/// Exchange an authorization code for an access token.
///
/// Validates client credentials (HTTP Basic auth preferred; falls back to
/// `client_id`/`client_secret` in the form body), ensures the provided
/// authorization code is single-use, unexpired, and bound to the same
/// client and redirect URI it was issued for, then issues a signed access
/// token for the OAuth audience.
///
/// # Returns
///
/// `TokenResponse` containing the issued access token JWT, the token type
/// set to `"Bearer"`, and `expires_in` with the token lifetime in seconds.
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

/// Resolve an access token to the user's OAuth profile for the relying party.
///
/// Verifies the Bearer access token, loads the account identified by the token's `sub` claim,
/// and returns a `UserInfoResponse` containing the stable subject and basic profile fields.
/// Returns `Unauthorized` if the bearer token is missing, invalid, or if the account no longer exists.
///
/// # Examples
///
/// ```
/// let resp = UserInfoResponse {
///     sub: "user-123".into(),
///     username: "alice".into(),
///     email: "alice@example.com".into(),
///     name: "Alice".into(),
///     avatar_url: "https://example.com/avatar.png".into(),
///     bio: "Example user".into(),
/// };
/// assert_eq!(resp.username, "alice");
/// ```
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

/// Validates that a redirect URI is a well-formed URL and permitted for the given client.
///
/// Returns `Err(AppError::BadRequest(_))` if the URI is not a valid URL or does not start with
/// the client's configured `redirect_uri_prefix`.
///
/// # Examples
///
/// ```
/// let client = ClientConfig { redirect_uri_prefix: "https://example.com/cb".into(), client_id: "c".into(), client_secret: "s".into() };
/// assert!(ensure_redirect_uri_allowed(&client, "https://example.com/cb/path").is_ok());
/// assert!(ensure_redirect_uri_allowed(&client, "not-a-url").is_err());
/// assert!(ensure_redirect_uri_allowed(&client, "https://evil.com/cb").is_err());
/// ```
fn ensure_redirect_uri_allowed(client: &ClientConfig, redirect_uri: &str) -> Result<(), AppError> {
    let redirect_url = url::Url::parse(redirect_uri)
        .map_err(|_| AppError::BadRequest("redirect_uri is not a valid URL".into()))?;

    // Reject redirect URIs with fragments per OAuth 2.0 spec
    if redirect_url.fragment().is_some() {
        return Err(AppError::BadRequest(
            "redirect_uri must not contain fragment".into(),
        ));
    }

    let prefix_url = url::Url::parse(&client.redirect_uri_prefix)
        .map_err(|_| AppError::BadRequest("redirect_uri_prefix is not a valid URL".into()))?;

    // Exact match on scheme, host, and port
    if redirect_url.scheme() != prefix_url.scheme()
        || redirect_url.host_str() != prefix_url.host_str()
        || redirect_url.port_or_known_default() != prefix_url.port_or_known_default()
    {
        return Err(AppError::BadRequest(
            "redirect_uri is not allowed for this client".into(),
        ));
    }

    // Path-prefix semantics: either exact match or prefix followed by separator
    let redirect_path = redirect_url.path();
    let prefix_path = prefix_url.path();

    if prefix_path == "/" {
        // Allow any path when prefix is just "/"
        return Ok(());
    }

    if redirect_path == prefix_path {
        // Exact path match
        return Ok(());
    }

    if redirect_path.starts_with(prefix_path) {
        // Must be followed by a path separator
        if redirect_path.len() > prefix_path.len()
            && redirect_path.as_bytes()[prefix_path.len()] == b'/'
        {
            return Ok(());
        }
    }

    Err(AppError::BadRequest(
        "redirect_uri is not allowed for this client".into(),
    ))
}

/// Percent-decodes a component string using form URL decoding rules.
///
/// Returns the decoded string. If the input contains no percent-encoded characters,
/// returns it unchanged.
///
/// # Examples
///
/// ```
/// assert_eq!(percent_decode_component("hello"), "hello");
/// assert_eq!(percent_decode_component("hello%20world"), "hello world");
/// assert_eq!(percent_decode_component("id%3Avalue"), "id:value");
/// ```
fn percent_decode_component(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes())
        .next()
        .map(|(k, _)| k.into_owned())
        .unwrap_or_else(|| s.to_string())
}

/// Extracts HTTP Basic credentials from the `Authorization` header.
///
/// Returns a tuple `(client_id, client_secret)` when a valid Basic auth header
/// is present and decodes to `id:secret`. Returns `(None, None)` if the header
/// is missing, not Basic auth, not valid base64, not UTF-8, or does not contain
/// a `:` separator.
///
/// # Examples
///
/// ```
/// use http::header::AUTHORIZATION;
/// use http::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert(
///     AUTHORIZATION,
///     "Basic dGVzdGlkOnNlY3JldA==".parse().unwrap(), // "testid:secret"
/// );
///
/// let (id, secret) = parse_basic_auth(&headers);
/// assert_eq!(id.as_deref(), Some("testid"));
/// assert_eq!(secret.as_deref(), Some("secret"));
/// ```
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
    // Clients are allowed to percent-encode the two components per RFC 6749
    // section 2.3.1 (application/x-www-form-urlencoded) before joining them
    // with `:`. We decode both components to handle this correctly.
    let Some((id_raw, secret_raw)) = as_str.split_once(':') else {
        return (None, None);
    };

    // Percent-decode both components using form URL decoding
    let id_decoded = percent_decode_component(id_raw);
    let secret_decoded = percent_decode_component(secret_raw);

    (Some(id_decoded), Some(secret_decoded))
}

/// Performs a constant-time equality check of two byte slices.
///
/// This function compares the contents without data-dependent early exits to
/// mitigate timing side channels.
///
/// # Returns
///
/// `true` if the slices have identical contents and equal length, `false` otherwise.
///
/// # Examples
///
/// ```
/// assert!(constant_time_eq(b"secret", b"secret"));
/// assert!(!constant_time_eq(b"secret", b"secreT"));
/// assert!(!constant_time_eq(b"short", b"shorter"));
/// ```
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

/// Generates a URL-safe opaque token by encoding `bytes` cryptographically secure random bytes using base64 (URL-safe, no padding).
///
/// # Examples
///
/// ```
/// let tok = random_opaque_token(32);
/// assert!(!tok.is_empty());
/// ```
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

    /// Ensures an authorization code is single-use: taking it removes it from the store.
    ///
    /// # Examples
    ///
    /// ```
    /// let store = AuthCodeStore::new();
    /// store.insert(
    ///     "c".into(),
    ///     AuthCode {
    ///         user_id: "u".into(),
    ///         client_id: "cid".into(),
    ///         redirect_uri: "http://x/".into(),
    ///         expires_at: i64::MAX,
    ///     },
    /// );
    /// assert!(store.take("c").is_some());
    /// assert!(store.take("c").is_none());
    /// ```
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