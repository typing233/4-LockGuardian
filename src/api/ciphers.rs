use actix_web::{web, HttpResponse};
use serde::Deserialize;
use serde_json::Value;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::cipher::Cipher;
use crate::models::event::{
    Event, EVENT_CIPHER_CREATED, EVENT_CIPHER_DELETED, EVENT_CIPHER_RESTORED,
    EVENT_CIPHER_UPDATED,
};
use crate::models::organization::{
    UserOrganization, ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN, ORG_USER_TYPE_OWNER,
};

/// Check if user can read a cipher (personal or org-based with proper access).
async fn check_cipher_read(
    pool: &SqlitePool,
    cipher: &Cipher,
    user_uuid: &str,
) -> Result<(), AppError> {
    // Personal cipher
    if cipher.user_uuid.as_deref() == Some(user_uuid) {
        return Ok(());
    }
    // Org cipher - verify membership and access
    if let Some(org_uuid) = &cipher.organization_uuid {
        let uo = UserOrganization::find_by_user_and_org(pool, user_uuid, org_uuid)
            .await?
            .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;
        if uo.status != ORG_USER_STATUS_CONFIRMED {
            return Err(AppError::Forbidden("Membership not confirmed".to_string()));
        }
        // Owner/Admin/access_all can read all
        if uo.type_ <= ORG_USER_TYPE_ADMIN || uo.access_all {
            return Ok(());
        }
        // Check collection-level access
        let has_access: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM ciphers_collections cc
             INNER JOIN users_collections uc ON uc.collection_uuid = cc.collection_uuid
             WHERE cc.cipher_uuid = ? AND uc.user_uuid = ?
             LIMIT 1"
        )
        .bind(&cipher.uuid)
        .bind(user_uuid)
        .fetch_optional(pool)
        .await?;
        if has_access.is_some() {
            return Ok(());
        }
        return Err(AppError::Forbidden("No access to this cipher".to_string()));
    }
    Err(AppError::Forbidden("Access denied".to_string()))
}

/// Check if user can write (create/update/delete) a cipher.
async fn check_cipher_write(
    pool: &SqlitePool,
    cipher: &Cipher,
    user_uuid: &str,
) -> Result<(), AppError> {
    // Personal cipher
    if cipher.user_uuid.as_deref() == Some(user_uuid) {
        return Ok(());
    }
    // Org cipher
    if let Some(org_uuid) = &cipher.organization_uuid {
        let uo = UserOrganization::find_by_user_and_org(pool, user_uuid, org_uuid)
            .await?
            .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;
        if uo.status != ORG_USER_STATUS_CONFIRMED {
            return Err(AppError::Forbidden("Membership not confirmed".to_string()));
        }
        // Owner/Admin can write all
        if uo.type_ <= ORG_USER_TYPE_ADMIN {
            return Ok(());
        }
        // access_all grants write
        if uo.access_all {
            return Ok(());
        }
        // Check collection-level write (not read_only)
        let has_write: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM ciphers_collections cc
             INNER JOIN users_collections uc ON uc.collection_uuid = cc.collection_uuid
             WHERE cc.cipher_uuid = ? AND uc.user_uuid = ? AND uc.read_only = 0
             LIMIT 1"
        )
        .bind(&cipher.uuid)
        .bind(user_uuid)
        .fetch_optional(pool)
        .await?;
        if has_write.is_some() {
            return Ok(());
        }
        return Err(AppError::Forbidden("Read-only access to this cipher".to_string()));
    }
    Err(AppError::Forbidden("Access denied".to_string()))
}

/// Check if user can create ciphers in an org.
async fn check_org_create_access(
    pool: &SqlitePool,
    org_uuid: &str,
    user_uuid: &str,
) -> Result<(), AppError> {
    let uo = UserOrganization::find_by_user_and_org(pool, user_uuid, org_uuid)
        .await?
        .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;
    if uo.status != ORG_USER_STATUS_CONFIRMED {
        return Err(AppError::Forbidden("Membership not confirmed".to_string()));
    }
    Ok(())
}

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

    check_cipher_read(&pool, &cipher, &user.uuid).await?;

    Ok(HttpResponse::Ok().json(cipher.to_json(&config.domain)))
}

pub async fn create(
    user: AuthenticatedUser,
    body: web::Json<CipherRequest>,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    // If creating in an org, verify membership
    if let Some(org_id) = &body.organization_id {
        check_org_create_access(&pool, org_id, &user.uuid).await?;
    }

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

    Event::log(
        &pool,
        EVENT_CIPHER_CREATED,
        cipher.user_uuid.as_deref(),
        cipher.organization_uuid.as_deref(),
        Some(&cipher.uuid),
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to log cipher create event: {}", e);
        e
    })
    .ok();

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

    check_cipher_write(&pool, &cipher, &user.uuid).await?;

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

    Event::log(
        &pool,
        EVENT_CIPHER_UPDATED,
        updated.user_uuid.as_deref(),
        updated.organization_uuid.as_deref(),
        Some(&uuid),
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to log cipher update event: {}", e);
        e
    })
    .ok();

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

    check_cipher_write(&pool, &cipher, &user.uuid).await?;

    Cipher::soft_delete(&pool, &uuid).await?;

    Event::log(
        &pool,
        EVENT_CIPHER_DELETED,
        cipher.user_uuid.as_deref(),
        cipher.organization_uuid.as_deref(),
        Some(&uuid),
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to log cipher soft-delete event: {}", e);
        e
    })
    .ok();

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

    check_cipher_write(&pool, &cipher, &user.uuid).await?;

    Cipher::hard_delete(&pool, &uuid).await?;

    Event::log(
        &pool,
        EVENT_CIPHER_DELETED,
        cipher.user_uuid.as_deref(),
        cipher.organization_uuid.as_deref(),
        Some(&uuid),
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to log cipher hard-delete event: {}", e);
        e
    })
    .ok();

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

    check_cipher_write(&pool, &cipher, &user.uuid).await?;

    Cipher::restore(&pool, &uuid).await?;

    Event::log(
        &pool,
        EVENT_CIPHER_RESTORED,
        cipher.user_uuid.as_deref(),
        cipher.organization_uuid.as_deref(),
        Some(&uuid),
        None,
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to log cipher restore event: {}", e);
        e
    })
    .ok();

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
            if check_cipher_write(&pool, &cipher, &user.uuid).await.is_ok() {
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
            if check_cipher_write(&pool, &cipher, &user.uuid).await.is_ok() {
                Cipher::restore(&pool, id).await?;
            }
        }
    }
    Ok(HttpResponse::Ok().finish())
}
