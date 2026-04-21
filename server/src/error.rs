use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrBody<'a> {
    error: &'a str,
    message: String,
}

impl IntoResponse for AppError {
    /// Convert an `AppError` into an HTTP response with an appropriate status code and JSON body.
    ///
    /// The response body is a JSON object `{ "error": <kind>, "message": <message> }` where
    /// `error` is a static error kind label and `message` is the human-readable message.
    /// For `Sqlx` and `Anyhow` errors (except `sqlx::Error::RowNotFound`), the error is logged
    /// and the response uses status `500` with message `"internal server error"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use axum::response::IntoResponse;
    /// use axum::http::StatusCode;
    ///
    /// let resp = crate::error::AppError::NotFound("item".into()).into_response();
    /// assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    /// ```
    fn into_response(self) -> Response {
        let (status, kind) = match &self {
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::Sqlx(sqlx::Error::RowNotFound) => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Sqlx(_) | AppError::Anyhow(_) => {
                tracing::error!(error = ?self, "internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "internal server error".to_owned()
        } else {
            self.to_string()
        };
        (
            status,
            Json(ErrBody {
                error: kind,
                message,
            }),
        )
            .into_response()
    }
}
