use actix_web::{dev::Payload, web, FromRequest, HttpRequest};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::crypto::RsaKeys;
use crate::error::AppError;

pub struct AuthenticatedUser {
    pub uuid: String,
    pub email: String,
    pub name: String,
    pub premium: bool,
    pub security_stamp: String,
    pub device_uuid: String,
}

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| AppError::Unauthorized("Missing authorization header".to_string()))?;

            let token = auth_header
                .strip_prefix("Bearer ")
                .ok_or_else(|| AppError::Unauthorized("Invalid authorization format".to_string()))?;

            let rsa_keys = req
                .app_data::<web::Data<Arc<RsaKeys>>>()
                .ok_or_else(|| AppError::Internal("RSA keys not configured".to_string()))?;

            let claims = super::token::validate_token(token, &rsa_keys.decoding_key)
                .map_err(|e| AppError::Unauthorized(format!("Invalid token: {}", e)))?;

            let pool = req
                .app_data::<web::Data<SqlitePool>>()
                .ok_or_else(|| AppError::Internal("Database pool not configured".to_string()))?;

            // Verify security stamp is still valid
            let user_stamp: Option<(String,)> =
                sqlx::query_as("SELECT security_stamp FROM users WHERE uuid = ?")
                    .bind(&claims.sub)
                    .fetch_optional(pool.get_ref())
                    .await
                    .map_err(|e| AppError::Internal(e.to_string()))?;

            match user_stamp {
                Some((stamp,)) if stamp == claims.sstamp => Ok(AuthenticatedUser {
                    uuid: claims.sub,
                    email: claims.email,
                    name: claims.name,
                    premium: claims.premium,
                    security_stamp: claims.sstamp,
                    device_uuid: claims.device,
                }),
                Some(_) => Err(AppError::Unauthorized(
                    "Security stamp mismatch".to_string(),
                )),
                None => Err(AppError::Unauthorized("User not found".to_string())),
            }
        })
    }
}
