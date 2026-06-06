use actix_web::{HttpResponse, ResponseError};
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Forbidden(String),
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal Error: {}", msg),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::BadRequest(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "Object": "error",
                "Message": msg,
                "ValidationErrors": null,
            })),
            AppError::Unauthorized(msg) => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": msg,
                "ErrorModel": {
                    "Object": "error",
                    "Message": msg,
                }
            })),
            AppError::NotFound(msg) => HttpResponse::NotFound().json(serde_json::json!({
                "Object": "error",
                "Message": msg,
            })),
            AppError::Forbidden(msg) => HttpResponse::Forbidden().json(serde_json::json!({
                "Object": "error",
                "Message": msg,
            })),
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "Object": "error",
                    "Message": "An internal error occurred",
                }))
            }
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::Unauthorized(err.to_string())
    }
}
