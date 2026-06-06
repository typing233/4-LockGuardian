use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::auth::two_factor;
use crate::crypto::RsaKeys;
use crate::error::AppError;
use crate::models::device::Device;
use crate::models::event::{Event, EVENT_USER_LOGGED_IN};
use crate::models::user::User;

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default, rename = "deviceIdentifier")]
    pub device_identifier: Option<String>,
    #[serde(default, rename = "deviceName")]
    pub device_name: Option<String>,
    #[serde(default, rename = "deviceType")]
    pub device_type: Option<i32>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default, rename = "twoFactorToken")]
    pub two_factor_token: Option<String>,
    #[serde(default, rename = "twoFactorProvider")]
    pub two_factor_provider: Option<i32>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default, rename = "client_id")]
    pub client_id: Option<String>,
}

pub async fn login(
    form: web::Form<TokenRequest>,
    pool: web::Data<SqlitePool>,
    rsa_keys: web::Data<Arc<RsaKeys>>,
    config: web::Data<crate::config::AppConfig>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    match form.grant_type.as_str() {
        "password" => handle_password_grant(&form, &pool, &rsa_keys, &config, &req).await,
        "refresh_token" => handle_refresh_grant(&form, &pool, &rsa_keys, &config).await,
        "client_credentials" => {
            // API key auth - return basic token
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "access_token": "",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}

async fn handle_password_grant(
    form: &TokenRequest,
    pool: &SqlitePool,
    rsa_keys: &Arc<RsaKeys>,
    config: &crate::config::AppConfig,
    _req: &HttpRequest,
) -> Result<HttpResponse, AppError> {
    let email = form
        .username
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Username required".to_string()))?;
    let password = form
        .password
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Password required".to_string()))?;
    let device_id = form
        .device_identifier
        .as_deref()
        .unwrap_or("unknown");
    let device_name = form.device_name.as_deref().unwrap_or("Unknown Device");
    let device_type = form.device_type.unwrap_or(0);

    let user = User::find_by_email(pool, email)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid username or password".to_string()))?;

    if !crate::crypto::verify_password(password, &user.password_hash) {
        return Err(AppError::Unauthorized(
            "Invalid username or password".to_string(),
        ));
    }

    // Check 2FA
    let twofactor: Option<(String, i32, String)> = sqlx::query_as(
        "SELECT uuid, type_, data FROM twofactor WHERE user_uuid = ? AND enabled = 1",
    )
    .bind(&user.uuid)
    .fetch_optional(pool)
    .await?;

    if let Some((_tf_uuid, tf_type, tf_data)) = &twofactor {
        // 2FA is enabled - check if token provided
        if let Some(token) = &form.two_factor_token {
            let provider = form.two_factor_provider.unwrap_or(0);
            if provider == 0 {
                // TOTP
                if !two_factor::verify_totp(tf_data, token) {
                    return Err(AppError::Unauthorized("Invalid 2FA code".to_string()));
                }
            } else {
                return Err(AppError::Unauthorized(
                    "Unsupported 2FA provider".to_string(),
                ));
            }
        } else {
            // Return 2FA required response
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two factor required.",
                "TwoFactorProviders": [*tf_type],
                "TwoFactorProviders2": {
                    tf_type.to_string(): null
                },
                "MasterPasswordPolicy": null,
            })));
        }
    }

    let device = Device::create_or_update(pool, &user.uuid, device_id, device_name, device_type)
        .await?;

    // Log login event
    Event::log(
        pool,
        EVENT_USER_LOGGED_IN,
        Some(&user.uuid),
        None,
        None,
        None,
        Some(&user.uuid),
        Some(device_type),
        None,
    )
    .await
    .ok();

    let access_token = crate::auth::token::generate_access_token(
        &user.uuid,
        &user.email,
        &user.name,
        user.premium,
        &user.security_stamp,
        &device.uuid,
        &config.domain,
        &rsa_keys.encoding_key,
    )
    .map_err(|e| AppError::Internal(format!("Token generation failed: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "access_token": access_token,
        "expires_in": 7200,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "Key": user.key_,
        "PrivateKey": user.private_key,
        "Kdf": user.kdf_type,
        "KdfIterations": user.kdf_iterations,
        "KdfMemory": user.kdf_memory,
        "KdfParallelism": user.kdf_parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "scope": "api offline_access",
        "unofficialServer": true,
        "UserDecryptionOptions": {
            "Object": "userDecryptionOptions",
            "HasMasterPassword": true,
        },
    })))
}

async fn handle_refresh_grant(
    form: &TokenRequest,
    pool: &SqlitePool,
    rsa_keys: &Arc<RsaKeys>,
    config: &crate::config::AppConfig,
) -> Result<HttpResponse, AppError> {
    let refresh_token = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Refresh token required".to_string()))?;

    let device = Device::find_by_refresh_token(pool, refresh_token)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

    let user = User::find_by_uuid(pool, &device.user_uuid)
        .await?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    // Generate new refresh token
    let new_device = Device::create_or_update(
        pool,
        &user.uuid,
        &device.uuid,
        &device.name,
        device.type_,
    )
    .await?;

    let access_token = crate::auth::token::generate_access_token(
        &user.uuid,
        &user.email,
        &user.name,
        user.premium,
        &user.security_stamp,
        &device.uuid,
        &config.domain,
        &rsa_keys.encoding_key,
    )
    .map_err(|e| AppError::Internal(format!("Token generation failed: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "access_token": access_token,
        "expires_in": 7200,
        "token_type": "Bearer",
        "refresh_token": new_device.refresh_token,
        "Key": user.key_,
        "PrivateKey": user.private_key,
        "Kdf": user.kdf_type,
        "KdfIterations": user.kdf_iterations,
        "KdfMemory": user.kdf_memory,
        "KdfParallelism": user.kdf_parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "scope": "api offline_access",
        "unofficialServer": true,
        "UserDecryptionOptions": {
            "Object": "userDecryptionOptions",
            "HasMasterPassword": true,
        },
    })))
}
