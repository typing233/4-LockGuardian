use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use futures::StreamExt;
use sqlx::SqlitePool;
use std::path::PathBuf;

use crate::auth::middleware::AuthenticatedUser;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::attachment::Attachment;
use crate::models::cipher::Cipher;

pub async fn upload(
    user: AuthenticatedUser,
    path: web::Path<String>,
    mut payload: Multipart,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let cipher_uuid = path.into_inner();

    let cipher = Cipher::find_by_uuid(&pool, &cipher_uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    let attachments_dir = PathBuf::from(&config.attachments_folder).join(&cipher_uuid);
    tokio::fs::create_dir_all(&attachments_dir)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create directory: {}", e)))?;

    let mut file_name = String::new();
    let mut file_size: i64 = 0;
    let mut key: Option<String> = None;
    let mut attachment_id = String::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| AppError::Internal(format!("Multipart error: {}", e)))?;
        let field_name = field
            .content_disposition()
            .and_then(|cd| cd.get_name().map(|s| s.to_string()))
            .unwrap_or_default();

        if field_name == "key" {
            let mut data = Vec::new();
            while let Some(chunk) = field.next().await {
                let chunk =
                    chunk.map_err(|e| AppError::Internal(format!("Chunk error: {}", e)))?;
                data.extend_from_slice(&chunk);
            }
            key = Some(String::from_utf8_lossy(&data).to_string());
        } else if field_name == "data" {
            file_name = field
                .content_disposition()
                .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
                .unwrap_or_else(|| "attachment".to_string());

            attachment_id = uuid::Uuid::new_v4().to_string();
            let file_path = attachments_dir.join(&attachment_id);

            let mut data = Vec::new();
            while let Some(chunk) = field.next().await {
                let chunk =
                    chunk.map_err(|e| AppError::Internal(format!("Chunk error: {}", e)))?;
                data.extend_from_slice(&chunk);
            }
            file_size = data.len() as i64;

            tokio::fs::write(&file_path, &data)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to write file: {}", e)))?;
        }
    }

    if file_name.is_empty() {
        return Err(AppError::BadRequest("No file uploaded".to_string()));
    }

    let attachment = Attachment::create(
        &pool,
        &cipher_uuid,
        &file_name,
        file_size,
        key.as_deref(),
    )
    .await?;

    // Return updated cipher with attachment
    let updated_cipher = Cipher::find_by_uuid(&pool, &cipher_uuid)
        .await?
        .ok_or_else(|| AppError::Internal("Cipher disappeared".to_string()))?;

    let mut cipher_json = updated_cipher.to_json(&config.domain);
    let attachments = Attachment::find_by_cipher(&pool, &cipher_uuid).await?;
    let att_json: Vec<_> = attachments
        .iter()
        .map(|a| a.to_json(&config.domain))
        .collect();
    cipher_json["Attachments"] = serde_json::json!(att_json);

    Ok(HttpResponse::Ok().json(cipher_json))
}

pub async fn download(
    path: web::Path<(String, String)>,
    config: web::Data<AppConfig>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (cipher_id, attachment_id) = path.into_inner();

    let _attachment = Attachment::find_by_id(&pool, &attachment_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Attachment not found".to_string()))?;

    let file_path = PathBuf::from(&config.attachments_folder)
        .join(&cipher_id)
        .join(&attachment_id);

    let data = tokio::fs::read(&file_path)
        .await
        .map_err(|e| AppError::NotFound(format!("File not found: {}", e)))?;

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(data))
}

pub async fn delete_attachment(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let (cipher_uuid, attachment_id) = path.into_inner();

    let cipher = Cipher::find_by_uuid(&pool, &cipher_uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // Delete file
    let file_path = PathBuf::from(&config.attachments_folder)
        .join(&cipher_uuid)
        .join(&attachment_id);
    tokio::fs::remove_file(&file_path).await.ok();

    // Delete DB record
    Attachment::delete(&pool, &attachment_id).await?;

    Ok(HttpResponse::Ok().finish())
}
