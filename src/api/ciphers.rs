use actix_web::{web, HttpResponse};
use serde::Deserialize;
use serde_json::Value;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::cipher::Cipher;

#[derive(Deserialize)]
pub struct CipherRequest {
    #[serde(rename = "type", alias = "Type")]
    pub type_: i32,
    #[serde(rename = "name", alias = "Name")]
    pub name: String,
    #[serde(rename = "notes", alias = "Notes")]
    pub notes: Option<String>,
    #[serde(rename = "fields", alias = "Fields")]
    pub fields: Option<Value>,
    #[serde(rename = "login", alias = "Login")]
    pub login: Option<Value>,
    #[serde(rename = "secureNote", alias = "SecureNote")]
    pub secure_note: Option<Value>,
    #[serde(rename = "card", alias = "Card")]
    pub card: Option<Value>,
    #[serde(rename = "identity", alias = "Identity")]
    pub identity: Option<Value>,
    #[serde(rename = "favorite", alias = "Favorite")]
    pub favorite: Option<bool>,
    #[serde(rename = "reprompt", alias = "Reprompt")]
    pub reprompt: Option<i32>,
    #[serde(rename = "folderId", alias = "FolderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "organizationId", alias = "OrganizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "collectionIds", alias = "CollectionIds")]
    pub collection_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct BulkDeleteRequest {
    #[serde(rename = "ids", alias = "Ids")]
    pub ids: Vec<String>,
}

impl CipherRequest {
    fn get_data(&self) -> String {
        let data = match self.type_ {
            1 => self.login.as_ref(),
            2 => self.secure_note.as_ref(),
            3 => self.card.as_ref(),
            4 => self.identity.as_ref(),
            _ => self.login.as_ref(),
        };
        data.map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string())
    }
}

pub async fn list(
    user: AuthenticatedUser,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let ciphers = Cipher::find_by_user(&pool, &user.uuid).await?;
    let data: Vec<_> = ciphers.iter().map(|c| c.to_json(&config.domain)).collect();

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
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let cipher = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(cipher.to_json(&config.domain)))
}

pub async fn create(
    user: AuthenticatedUser,
    body: web::Json<CipherRequest>,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let data = body.get_data();
    let fields = body.fields.as_ref().map(|f| f.to_string());

    let cipher = Cipher::create(
        &pool,
        if body.organization_id.is_some() {
            None
        } else {
            Some(&user.uuid)
        },
        body.organization_id.as_deref(),
        body.type_,
        &body.name,
        body.notes.as_deref(),
        fields.as_deref(),
        &data,
        body.favorite.unwrap_or(false),
        body.reprompt.unwrap_or(0),
        body.folder_id.as_deref(),
    )
    .await?;

    // Handle collection assignments
    if let Some(collection_ids) = &body.collection_ids {
        for coll_id in collection_ids {
            crate::models::collection::Collection::add_cipher(&pool, coll_id, &cipher.uuid)
                .await?;
        }
    }

    Ok(HttpResponse::Ok().json(cipher.to_json(&config.domain)))
}

pub async fn update(
    user: AuthenticatedUser,
    path: web::Path<String>,
    body: web::Json<CipherRequest>,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let cipher = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    let data = body.get_data();
    let fields = body.fields.as_ref().map(|f| f.to_string());

    Cipher::update(
        &pool,
        &uuid,
        &body.name,
        body.notes.as_deref(),
        fields.as_deref(),
        &data,
        body.favorite.unwrap_or(false),
        body.reprompt.unwrap_or(0),
        body.folder_id.as_deref(),
    )
    .await?;

    let updated = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::Internal("Cipher disappeared".to_string()))?;

    Ok(HttpResponse::Ok().json(updated.to_json(&config.domain)))
}

pub async fn soft_delete(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let cipher = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Cipher::soft_delete(&pool, &uuid).await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn hard_delete(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let cipher = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Cipher::hard_delete(&pool, &uuid).await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn restore(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let uuid = path.into_inner();
    let cipher = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    if cipher.user_uuid.as_deref() != Some(&user.uuid) && cipher.organization_uuid.is_none() {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Cipher::restore(&pool, &uuid).await?;

    let restored = Cipher::find_by_uuid(&pool, &uuid)
        .await?
        .ok_or_else(|| AppError::Internal("Cipher disappeared".to_string()))?;

    Ok(HttpResponse::Ok().json(restored.to_json(&config.domain)))
}

pub async fn bulk_soft_delete(
    user: AuthenticatedUser,
    body: web::Json<BulkDeleteRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    for id in &body.ids {
        if let Some(cipher) = Cipher::find_by_uuid(&pool, id).await? {
            if cipher.user_uuid.as_deref() == Some(&user.uuid)
                || cipher.organization_uuid.is_some()
            {
                Cipher::soft_delete(&pool, id).await?;
            }
        }
    }
    Ok(HttpResponse::Ok().finish())
}

pub async fn bulk_restore(
    user: AuthenticatedUser,
    body: web::Json<BulkDeleteRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    for id in &body.ids {
        if let Some(cipher) = Cipher::find_by_uuid(&pool, id).await? {
            if cipher.user_uuid.as_deref() == Some(&user.uuid)
                || cipher.organization_uuid.is_some()
            {
                Cipher::restore(&pool, id).await?;
            }
        }
    }
    Ok(HttpResponse::Ok().finish())
}
