use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::cipher::Cipher;
use crate::models::folder::Folder;
use crate::models::user::User;

#[derive(Deserialize)]
pub struct RegisterRequest {
    #[serde(rename = "email", alias = "Email")]
    pub email: String,
    #[serde(rename = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(rename = "masterPasswordHint", alias = "MasterPasswordHint")]
    pub master_password_hint: Option<String>,
    #[serde(rename = "name", alias = "Name")]
    pub name: Option<String>,
    #[serde(rename = "key", alias = "Key")]
    pub key: Option<String>,
    #[serde(rename = "keys", alias = "Keys")]
    pub keys: Option<KeysRequest>,
    #[serde(rename = "kdf", alias = "Kdf")]
    pub kdf: Option<i32>,
    #[serde(rename = "kdfIterations", alias = "KdfIterations")]
    pub kdf_iterations: Option<i32>,
    #[serde(rename = "kdfMemory", alias = "KdfMemory")]
    pub kdf_memory: Option<i32>,
    #[serde(rename = "kdfParallelism", alias = "KdfParallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Deserialize)]
pub struct KeysRequest {
    #[serde(rename = "publicKey", alias = "PublicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "encryptedPrivateKey", alias = "EncryptedPrivateKey")]
    pub encrypted_private_key: Option<String>,
}

#[derive(Deserialize)]
pub struct PreloginRequest {
    #[serde(rename = "email", alias = "Email")]
    pub email: String,
}

#[derive(Deserialize)]
pub struct ProfileUpdateRequest {
    #[serde(rename = "name", alias = "Name")]
    pub name: Option<String>,
    #[serde(rename = "masterPasswordHint", alias = "MasterPasswordHint")]
    pub master_password_hint: Option<String>,
}

#[derive(Deserialize)]
pub struct PostKeysRequest {
    #[serde(rename = "publicKey", alias = "PublicKey")]
    pub public_key: String,
    #[serde(rename = "encryptedPrivateKey", alias = "EncryptedPrivateKey")]
    pub encrypted_private_key: String,
}

pub async fn register(
    body: web::Json<RegisterRequest>,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    if !config.signups_allowed {
        return Err(AppError::BadRequest("Signups are not allowed".to_string()));
    }

    if body.email.is_empty() || body.master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Email and password are required".to_string(),
        ));
    }

    // Check if user exists
    if User::find_by_email(&pool, &body.email).await?.is_some() {
        return Err(AppError::BadRequest(
            "User already exists".to_string(),
        ));
    }

    let password_hash = crate::crypto::hash_password(&body.master_password_hash)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?;

    let public_key = body
        .keys
        .as_ref()
        .and_then(|k| k.public_key.as_deref());
    let private_key = body
        .keys
        .as_ref()
        .and_then(|k| k.encrypted_private_key.as_deref());

    let _user = User::create(
        &pool,
        &body.email,
        body.name.as_deref().unwrap_or(""),
        &password_hash,
        "",
        body.kdf.unwrap_or(0),
        body.kdf_iterations.unwrap_or(600000),
        body.kdf_memory,
        body.kdf_parallelism,
        body.key.as_deref(),
        public_key,
        private_key,
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn prelogin(
    body: web::Json<PreloginRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    // Return KDF params; use defaults for non-existent users to prevent enumeration
    let (kdf, iterations, memory, parallelism) =
        if let Some(user) = User::find_by_email(&pool, &body.email).await? {
            (
                user.kdf_type,
                user.kdf_iterations,
                user.kdf_memory,
                user.kdf_parallelism,
            )
        } else {
            (0, 600000, None, None)
        };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Kdf": kdf,
        "KdfIterations": iterations,
        "KdfMemory": memory,
        "KdfParallelism": parallelism,
    })))
}

pub async fn profile(
    user: AuthenticatedUser,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(HttpResponse::Ok().json(user_profile_json(&db_user)))
}

pub async fn update_profile(
    user: AuthenticatedUser,
    body: web::Json<ProfileUpdateRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    if let Some(name) = &body.name {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE users SET name = ?, updated_at = ? WHERE uuid = ?")
            .bind(name)
            .bind(&now)
            .bind(&user.uuid)
            .execute(pool.get_ref())
            .await?;
    }

    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(HttpResponse::Ok().json(user_profile_json(&db_user)))
}

pub async fn post_keys(
    user: AuthenticatedUser,
    body: web::Json<PostKeysRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    User::update_keys(
        &pool,
        &user.uuid,
        db_user.key_.as_deref().unwrap_or(""),
        &body.public_key,
        &body.encrypted_private_key,
    )
    .await?;

    Ok(HttpResponse::Ok().json(user_profile_json(&db_user)))
}

pub async fn revision_date(user: AuthenticatedUser) -> Result<HttpResponse, AppError> {
    let now = chrono::Utc::now().timestamp_millis();
    Ok(HttpResponse::Ok().json(now))
}

pub async fn export_vault(
    user: AuthenticatedUser,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let ciphers = Cipher::find_by_user(&pool, &user.uuid).await?;
    let folders = Folder::find_by_user(&pool, &user.uuid).await?;

    let cipher_json: Vec<_> = ciphers.iter().map(|c| c.to_json(&config.domain)).collect();
    let folder_json: Vec<_> = folders.iter().map(|f| f.to_json()).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Folders": folder_json,
        "Ciphers": cipher_json,
    })))
}

fn user_profile_json(user: &User) -> serde_json::Value {
    serde_json::json!({
        "Object": "profile",
        "Id": user.uuid,
        "Name": user.name,
        "Email": user.email,
        "EmailVerified": user.email_verified,
        "Premium": user.premium,
        "MasterPasswordHint": null,
        "Culture": "en-US",
        "TwoFactorEnabled": false,
        "Key": user.key_,
        "PrivateKey": user.private_key,
        "SecurityStamp": user.security_stamp,
        "Organizations": [],
        "Providers": [],
        "ForcePasswordReset": false,
        "AvatarColor": null,
        "CreationDate": user.created_at,
    })
}
