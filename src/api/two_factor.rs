use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::auth::two_factor as tf;
use crate::error::AppError;
use crate::models::event::{Event, EVENT_USER_DISABLED_2FA, EVENT_USER_ENABLED_2FA};
use crate::models::user::User;

#[derive(Deserialize)]
pub struct AuthenticatorRequest {
    #[serde(rename = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(rename = "token", alias = "Token")]
    pub token: Option<String>,
    #[serde(rename = "key", alias = "Key")]
    pub key: Option<String>,
}

#[derive(Deserialize)]
pub struct DisableRequest {
    #[serde(rename = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(rename = "type", alias = "Type")]
    pub type_: i32,
}

#[derive(Deserialize)]
pub struct RecoverRequest {
    #[serde(rename = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(rename = "email", alias = "Email")]
    pub email: String,
    #[serde(rename = "recoveryCode", alias = "RecoveryCode")]
    pub recovery_code: String,
}

pub async fn get_authenticator(
    user: AuthenticatedUser,
    body: web::Json<AuthenticatorRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if !crate::crypto::verify_password(&body.master_password_hash, &db_user.password_hash) {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Check if TOTP already exists
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT data FROM twofactor WHERE user_uuid = ? AND type_ = 0")
            .bind(&user.uuid)
            .fetch_optional(pool.get_ref())
            .await?;

    let enabled = existing.is_some();
    let key = if let Some((data,)) = existing {
        data
    } else {
        tf::generate_totp_secret()
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "twoFactorAuthenticator",
        "Enabled": enabled,
        "Key": key,
    })))
}

pub async fn activate_authenticator(
    user: AuthenticatedUser,
    body: web::Json<AuthenticatorRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if !crate::crypto::verify_password(&body.master_password_hash, &db_user.password_hash) {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    let key = body
        .key
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Key required".to_string()))?;
    let token = body
        .token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Token required".to_string()))?;

    // Verify the token works with the key
    if !tf::verify_totp(key, token) {
        return Err(AppError::BadRequest(
            "Invalid TOTP token. Make sure your authenticator is synced.".to_string(),
        ));
    }

    // Save or update
    let uuid = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT OR REPLACE INTO twofactor (uuid, user_uuid, type_, enabled, data) VALUES (COALESCE((SELECT uuid FROM twofactor WHERE user_uuid = ? AND type_ = 0), ?), ?, 0, 1, ?)"
    )
    .bind(&user.uuid)
    .bind(&uuid)
    .bind(&user.uuid)
    .bind(key)
    .execute(pool.get_ref())
    .await?;

    // Update security stamp
    User::update_security_stamp(&pool, &user.uuid).await?;

    Event::log(
        &pool,
        EVENT_USER_ENABLED_2FA,
        Some(&user.uuid),
        None,
        None,
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "twoFactorAuthenticator",
        "Enabled": true,
        "Key": key,
    })))
}

pub async fn disable(
    user: AuthenticatedUser,
    body: web::Json<DisableRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if !crate::crypto::verify_password(&body.master_password_hash, &db_user.password_hash) {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    sqlx::query("DELETE FROM twofactor WHERE user_uuid = ? AND type_ = ?")
        .bind(&user.uuid)
        .bind(body.type_)
        .execute(pool.get_ref())
        .await?;

    User::update_security_stamp(&pool, &user.uuid).await?;

    Event::log(
        &pool,
        EVENT_USER_DISABLED_2FA,
        Some(&user.uuid),
        None,
        None,
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "twoFactorProvider",
        "Enabled": false,
        "Type": body.type_,
    })))
}

pub async fn get_recover(
    user: AuthenticatedUser,
    body: web::Json<AuthenticatorRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if !crate::crypto::verify_password(&body.master_password_hash, &db_user.password_hash) {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Recovery code is derived from the security stamp
    let code = &db_user.security_stamp[..8];

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "twoFactorRecover",
        "Code": code,
    })))
}

pub async fn recover(
    body: web::Json<RecoverRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_email(&pool, &body.email)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid recovery".to_string()))?;

    if !crate::crypto::verify_password(&body.master_password_hash, &db_user.password_hash) {
        return Err(AppError::Unauthorized("Invalid recovery".to_string()));
    }

    let expected_code = &db_user.security_stamp[..8];
    if body.recovery_code != expected_code {
        return Err(AppError::Unauthorized(
            "Invalid recovery code".to_string(),
        ));
    }

    // Disable all 2FA
    sqlx::query("DELETE FROM twofactor WHERE user_uuid = ?")
        .bind(&db_user.uuid)
        .execute(pool.get_ref())
        .await?;

    User::update_security_stamp(&pool, &db_user.uuid).await?;

    Ok(HttpResponse::Ok().finish())
}
