//! Password hashing, session-JWT issuance, and the register/login/me HTTP
//! handlers that the SPA uses to establish a local session with this
//! account directory. These flows are for logging the user into Zixiao
//! Cloud Account itself; the downstream OAuth authorize flow lives in
//! `oauth.rs` and layers on top of a session issued here.

use crate::{app_state::AppState, db::DbPool, error::AppError};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header::AUTHORIZATION},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub avatar_url: String,
    pub bio: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct UserRecord {
    id: String,
    username: String,
    email: String,
    display_name: String,
    avatar_url: String,
    bio: String,
    password_hash: String,
    created_at: i64,
    updated_at: i64,
}

impl UserRecord {
    /// Create a `UserProfile` by copying the public profile fields from this `UserRecord`.
    ///
    /// The returned `UserProfile` contains the record's `id`, `username`, `email`,
    /// `display_name`, `avatar_url`, `bio`, `created_at`, and `updated_at`.
    ///
    /// # Examples
    ///
    /// ```
    /// let rec = UserRecord {
    ///     id: "u1".into(),
    ///     username: "alice".into(),
    ///     email: "alice@example.com".into(),
    ///     display_name: "Alice".into(),
    ///     avatar_url: "".into(),
    ///     bio: "".into(),
    ///     password_hash: "$argon2id$...".into(),
    ///     created_at: 1_700_000_000,
    ///     updated_at: 1_700_000_000,
    /// };
    /// let profile = rec.to_profile();
    /// assert_eq!(profile.id, rec.id);
    /// assert_eq!(profile.username, rec.username);
    /// ```
    pub fn to_profile(&self) -> UserProfile {
        UserProfile {
            id: self.id.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
            bio: self.bio.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl From<UserRecord> for UserProfile {
    /// Create a UserProfile from a UserRecord by moving the record's profile fields.
    ///
    /// # Examples
    ///
    /// ```
    /// let rec = UserRecord {
    ///     id: "user-1".to_string(),
    ///     username: "alice".to_string(),
    ///     email: "alice@example.com".to_string(),
    ///     display_name: "Alice".to_string(),
    ///     avatar_url: "".to_string(),
    ///     bio: "".to_string(),
    ///     password_hash: "hashed".to_string(),
    ///     created_at: 0,
    ///     updated_at: 0,
    /// };
    /// let profile: UserProfile = UserProfile::from(rec);
    /// assert_eq!(profile.username, "alice");
    /// ```
    fn from(u: UserRecord) -> Self {
        UserProfile {
            id: u.id,
            username: u.username,
            email: u.email,
            display_name: u.display_name,
            avatar_url: u.avatar_url,
            bio: u.bio,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    /// Audience. Session JWTs use "session"; OAuth access tokens use
    /// "oauth". This lets a single secret sign both without letting an
    /// OAuth access token be replayed as a session cookie or vice versa.
    pub aud: String,
}

pub const SESSION_AUDIENCE: &str = "session";

/// Hashes a password with Argon2 using a randomly generated salt.
///
/// Returns the Argon2-encoded password hash as a `String` on success, or an `AppError::Anyhow` if hashing fails.
///
/// # Examples
///
/// ```
/// let hashed = hash_password("s3cret").expect("hashing failed");
/// assert!(hashed.contains("$argon2"));
/// ```
pub fn hash_password(plain: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Anyhow(anyhow::anyhow!("hash_password: {e}")))
}

/// Verifies whether a plaintext password matches a stored Argon2 password hash.
///
/// Returns `Ok(true)` if `plain` matches `hash`, `Ok(false)` if it does not,
/// and `Err(AppError::Anyhow)` if the stored hash cannot be parsed or another
/// hashing-related error occurs.
///
/// # Examples
///
/// ```
/// // Create a hash (helper `hash_password` is assumed available in the same module).
/// let stored = hash_password("s3cr3t").expect("hashing should succeed");
/// assert!(verify_password("s3cr3t", &stored).unwrap());
/// assert!(!verify_password("wrong", &stored).unwrap());
/// ```
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::Anyhow(anyhow::anyhow!("parse password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}

/// Creates a signed session JWT containing the user id as `sub`, issued-at (`iat`), expiry (`exp` = now + `ttl_secs`), and `aud`.
///
/// # Returns
///
/// `Ok(String)` with the encoded JWT on success, or `Err(AppError::Anyhow(_))` if encoding fails.
///
/// # Examples
///
/// ```
/// let secret = b"my-secret-key";
/// let token = issue_jwt(secret, "user-123", 3600, "session").unwrap();
/// assert!(!token.is_empty());
/// ```
pub fn issue_jwt(
    secret: &[u8],
    user_id: &str,
    ttl_secs: i64,
    audience: &str,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = SessionClaims {
        sub: user_id.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ttl_secs)).timestamp(),
        aud: audience.to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| AppError::Anyhow(anyhow::anyhow!("issue jwt: {e}")))
}

/// Verifies a JWT's signature, expiration, and audience and returns its session claims.

///

/// The provided `secret` is used to verify the token signature; the token's `aud` claim must match `audience`.

///

/// # Examples

///

/// ```

/// let secret = b"my-jwt-secret";

/// let token = "eyJ..."; // a JWT string

/// let result = verify_jwt(secret, token, "session");

/// match result {

///     Ok(claims) => println!("user id: {}", claims.sub),

///     Err(err) => eprintln!("verification failed: {:?}", err),

/// }

/// ```

///

/// # Returns

///

/// On success returns the decoded `SessionClaims`. On failure returns `AppError::Unauthorized("invalid or expired token")`.
pub fn verify_jwt(secret: &[u8], token: &str, audience: &str) -> Result<SessionClaims, AppError> {
    let mut validation = Validation::default();
    validation.set_audience(&[audience]);
    decode::<SessionClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|d| d.claims)
        .map_err(|_| AppError::Unauthorized("invalid or expired token".into()))
}

/// Get the bearer token string from the `Authorization` header.
///
/// Returns `Some(token)` containing the header value with the leading `"Bearer "` (case-insensitive)
/// prefix removed, or `None` if the header is missing, malformed, empty, or does not use the Bearer scheme.
///
/// # Examples
///
/// ```
/// use http::header::AUTHORIZATION;
/// use http::HeaderMap;
/// use http::HeaderValue;
///
/// let mut headers = HeaderMap::new();
/// headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc.def.ghi"));
/// assert_eq!(crate::auth::bearer_token(&headers), Some("abc.def.ghi".to_string()));
///
/// let mut headers = HeaderMap::new();
/// headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer xyz"));
/// assert_eq!(crate::auth::bearer_token(&headers), Some("xyz".to_string()));
///
/// let mut headers = HeaderMap::new();
/// headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic foo"));
/// assert_eq!(crate::auth::bearer_token(&headers), None);
/// ```
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let hv = headers.get(AUTHORIZATION)?;
    let s = hv.to_str().ok()?;
    let rest = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))?;
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username_or_email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserProfile,
}

/// Register a new user, persist their record, issue a session JWT, and return the token plus the created profile.
///
/// Validations:
/// - `username` and `email` are trimmed and must not be empty (otherwise returns `AppError::BadRequest`).
/// - `password` must be at least 8 characters (otherwise returns `AppError::BadRequest`).
/// - If the username or email is already taken the function returns `AppError::Conflict`.
/// On success returns an `AuthResponse` containing the issued session token and the new `UserProfile`.
///
/// # Examples
///
/// ```no_run
/// # use server::auth::{register, RegisterRequest, AppState};
/// # use axum::{extract::State, Json};
/// # async fn example(state: AppState) {
/// let req = RegisterRequest {
///     username: "alice".into(),
///     email: "alice@example.com".into(),
///     password: "s3cur3pass".into(),
///     display_name: "Alice".into(),
/// };
/// // handlers are async and normally invoked by the web framework:
/// let _resp = register(State(state), Json(req)).await;
/// # }
/// ```
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let username = req.username.trim();
    let email = req.email.trim();
    if username.is_empty() || email.is_empty() {
        return Err(AppError::BadRequest("username and email required".into()));
    }
    if req.password.len() < 8 {
        return Err(AppError::BadRequest("password must be >=8 chars".into()));
    }
    if find_user(&state.db, username).await?.is_some()
        || find_user(&state.db, email).await?.is_some()
    {
        return Err(AppError::Conflict("username or email already taken".into()));
    }
    let now = Utc::now().timestamp();
    let rec = UserRecord {
        id: Uuid::new_v4().to_string(),
        username: username.to_string(),
        email: email.to_string(),
        display_name: req.display_name,
        avatar_url: String::new(),
        bio: String::new(),
        password_hash: hash_password(&req.password)?,
        created_at: now,
        updated_at: now,
    };
    sqlx::query(
        "INSERT INTO users (id, username, email, display_name, avatar_url, bio, password_hash, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(&rec.id)
    .bind(&rec.username)
    .bind(&rec.email)
    .bind(&rec.display_name)
    .bind(&rec.avatar_url)
    .bind(&rec.bio)
    .bind(&rec.password_hash)
    .bind(rec.created_at)
    .bind(rec.updated_at)
    .execute(&state.db)
    .await?;
    let token = issue_jwt(
        state.config.jwt_secret.as_bytes(),
        &rec.id,
        state.config.session_ttl_secs,
        SESSION_AUDIENCE,
    )?;
    Ok(Json(AuthResponse {
        token,
        user: UserProfile::from(rec),
    }))
}

/// Authenticates a user by username or email and password and returns a session token together with the user's profile.
///
/// Looks up a user matching `req.username_or_email`, verifies `req.password` against the stored password hash, and issues a session JWT scoped to the session audience when credentials are valid.
/// On success returns `Ok(Json(AuthResponse))` containing the issued token and the corresponding `UserProfile`.
/// Returns `Err(AppError::Unauthorized("invalid credentials"))` if no matching user is found or the password verification fails.
///
/// # Examples
///
/// ```
/// // Example usage in an async context:
/// // let result = login(State(app_state), Json(login_request)).await;
/// // match result {
/// //     Ok(Json(auth)) => {
/// //         assert!(!auth.token.is_empty());
/// //         assert_eq!(auth.user.username, "alice");
/// //     }
/// //     Err(e) => panic!("authentication failed: {:?}", e),
/// // }
/// ```
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let user = find_user(&state.db, &req.username_or_email)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".into()))?;
    if !verify_password(&req.password, &user.password_hash)? {
        return Err(AppError::Unauthorized("invalid credentials".into()));
    }
    let token = issue_jwt(
        state.config.jwt_secret.as_bytes(),
        &user.id,
        state.config.session_ttl_secs,
        SESSION_AUDIENCE,
    )?;
    Ok(Json(AuthResponse {
        token,
        user: UserProfile::from(user),
    }))
}

/// Return the authenticated user's profile extracted from a session bearer token.
///
/// This handler extracts a bearer token from the request headers, verifies the token's
/// signature, expiry, and audience, looks up the user by the token subject, and returns
/// the user's profile as JSON. If the bearer token is missing or invalid, the function
/// returns an `AppError::Unauthorized`; if the referenced user does not exist, it returns
/// an `AppError::NotFound`.
///
/// # Returns
///
/// `Json<UserProfile>` containing the authenticated user's profile.
///
/// # Examples
///
/// ```no_run
/// use axum::{http::HeaderMap, Json, extract::State};
/// use server::auth::me;
/// use server::AppState;
/// use server::models::UserProfile;
///
/// #[tokio::main]
/// async fn main() {
///     // This example is illustrative: in a real server the `State` and `HeaderMap` come from Axum.
///     let state = /* construct AppState with DB and config */ unimplemented!();
///     let headers = HeaderMap::new(); // should contain "Authorization: Bearer <token>"
///
///     // Call the handler (in real usage Axum invokes this).
///     let _result: Result<Json<UserProfile>, _> = me(State(state), headers).await;
/// }
/// ```
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserProfile>, AppError> {
    let token = bearer_token(&headers)
        .ok_or_else(|| AppError::Unauthorized("missing bearer token".into()))?;
    let claims = verify_jwt(state.config.jwt_secret.as_bytes(), &token, SESSION_AUDIENCE)?;
    let user = find_user_by_id(&state.db, &claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("user".into()))?;
    Ok(Json(UserProfile::from(user)))
}

/// Fetches a user record by username or email from the database.
///
/// Searches the `users` table for a row where `username` or `email` equals `ident` and returns
/// the corresponding `UserRecord` when found.
///
/// `ident` may be either a username or an email address. Database/query errors are returned as
/// `AppError`.
///
/// # Returns
///
/// `Some(UserRecord)` if a matching user exists, `None` if no match is found.
///
/// # Examples
///
/// ```no_run
/// # async fn example(pool: &DbPool) {
/// let res = find_user(pool, "alice@example.com").await.unwrap();
/// if let Some(user) = res {
///     assert!(user.email == "alice@example.com" || user.username == "alice");
/// }
/// # }
/// ```
async fn find_user(pool: &DbPool, ident: &str) -> Result<Option<UserRecord>, AppError> {
    let row = sqlx::query(
        "SELECT id, username, email, display_name, avatar_url, bio, password_hash, created_at, updated_at \
         FROM users WHERE username = $1 OR email = $1",
    )
    .bind(ident)
    .fetch_optional(pool)
    .await?;
    row.map(user_from_row).transpose()
}

/// Fetches a user record by its id from the database.
///
/// Returns `Some(UserRecord)` when a user with the given `id` exists, `None` if no matching row is found.
/// Database or row-mapping failures are returned as an `AppError`.
///
/// # Examples
///
/// ```
/// # async fn example(pool: &DbPool) -> Result<(), AppError> {
/// let maybe_user = find_user_by_id(pool, "user-id-123").await?;
/// if let Some(user) = maybe_user {
///     assert_eq!(user.id, "user-id-123");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn find_user_by_id(pool: &DbPool, id: &str) -> Result<Option<UserRecord>, AppError> {
    let row = sqlx::query(
        "SELECT id, username, email, display_name, avatar_url, bio, password_hash, created_at, updated_at \
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(user_from_row).transpose()
}

/// Constructs a `UserRecord` by extracting the expected columns from a `SqliteRow`.
///
/// The function reads the following named columns from `row`: `id`, `username`, `email`,
/// `display_name`, `avatar_url`, `bio`, `password_hash`, `created_at`, and `updated_at`.
/// Returns `Err(AppError)` if any column is missing or cannot be converted to the expected type.
///
/// # Parameters
///
/// - `row`: A `sqlx::sqlite::SqliteRow` containing columns for a user record.
///
/// # Returns
///
/// `Ok(UserRecord)` with all fields populated on success, `Err(AppError)` if column extraction fails.
///
/// # Examples
///
/// ```no_run
/// # use sqlx::sqlite::SqliteRow;
/// # use crate::auth::{user_from_row, UserRecord};
/// // `row` would typically come from `sqlx::query(...).fetch_one(&pool).await?`
/// // let row: SqliteRow = ...;
/// // let user: UserRecord = user_from_row(row)?;
/// ```
fn user_from_row(row: sqlx::sqlite::SqliteRow) -> Result<UserRecord, AppError> {
    Ok(UserRecord {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        avatar_url: row.try_get("avatar_url")?,
        bio: row.try_get("bio")?,
        password_hash: row.try_get("password_hash")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
