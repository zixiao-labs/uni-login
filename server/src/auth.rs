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

pub fn hash_password(plain: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Anyhow(anyhow::anyhow!("hash_password: {e}")))
}

pub fn verify_password(plain: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::Anyhow(anyhow::anyhow!("parse password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}

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

pub fn verify_jwt(secret: &[u8], token: &str, audience: &str) -> Result<SessionClaims, AppError> {
    let mut validation = Validation::default();
    validation.set_audience(&[audience]);
    decode::<SessionClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|d| d.claims)
        .map_err(|_| AppError::Unauthorized("invalid or expired token".into()))
}

/// Extract the Bearer token from an Authorization header.
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
