use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::error::AppError;
use crate::models::folder::Folder;

#[derive(Deserialize)]
pub struct FolderRequest {
    #[serde(rename = "name", alias = "Name")]
    pub name: String,
}

pub async fn list(
    user: AuthenticatedUser,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let folders = Folder::find_by_user(&pool, &user.uuid).await?;
    let data: Vec<_> = folders.iter().map(|f| f.to_json()).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "list",
        "Data": data,
        "ContinuationToken": null,
    })))
}

pub async fn get(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let folder = Folder::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Folder not found".to_string()))?;

    if folder.user_uuid != user.uuid {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(folder.to_json()))
}

pub async fn create(
    user: AuthenticatedUser,
    body: web::Json<FolderRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let folder = Folder::create(&pool, &user.uuid, &body.name).await?;
    Ok(HttpResponse::Ok().json(folder.to_json()))
}

pub async fn update(
    user: AuthenticatedUser,
    path: web::Path<String>,
    body: web::Json<FolderRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let folder = Folder::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Folder not found".to_string()))?;

    if folder.user_uuid != user.uuid {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Folder::update(&pool, &uuid, &body.name).await?;

    let updated = Folder::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::Internal("Folder disappeared".to_string()))?;

    Ok(HttpResponse::Ok().json(updated.to_json()))
}

pub async fn delete(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let folder = Folder::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Folder not found".to_string()))?;

    if folder.user_uuid != user.uuid {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Folder::delete(&pool, &uuid).await?;
    Ok(HttpResponse::Ok().finish())
}
