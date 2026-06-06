use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::error::AppError;
use crate::models::collection::Collection;
use crate::models::event::{Event, EVENT_COLLECTION_CREATED};
use crate::models::organization::*;

#[derive(Deserialize)]
pub struct CollectionRequest {
    #[serde(rename = "name", alias = "Name")]
    pub name: String,
    #[serde(rename = "externalId", alias = "ExternalId")]
    pub external_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SetUsersRequest {
    #[serde(default)]
    pub users: Vec<CollectionUserEntry>,
}

#[derive(Deserialize)]
pub struct CollectionUserEntry {
    #[serde(rename = "id", alias = "Id")]
    pub id: String,
    #[serde(rename = "readOnly", alias = "ReadOnly")]
    pub read_only: Option<bool>,
    #[serde(rename = "hidePasswords", alias = "HidePasswords")]
    pub hide_passwords: Option<bool>,
}

pub async fn list(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org_id = path.into_inner();

    UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    let collections = Collection::find_by_org(&pool, &org_id).await?;
    let data: Vec<_> = collections.iter().map(|c| c.to_json()).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "list",
        "Data": data,
        "ContinuationToken": null,
    })))
}

pub async fn create(
    user: AuthenticatedUser,
    path: web::Path<String>,
    body: web::Json<CollectionRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org_id = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    let collection = Collection::create(&pool, &org_id, &body.name).await?;

    Event::log(
        &pool,
        EVENT_COLLECTION_CREATED,
        None,
        Some(&org_id),
        None,
        Some(&collection.uuid),
        Some(&user.uuid),
        None,
        None,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to log collection create event: {}", e);
        e
    })
    .ok();

    Ok(HttpResponse::Ok().json(collection.to_json()))
}

pub async fn get(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, coll_id) = path.into_inner();

    UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    let collection = Collection::find_by_uuid(&pool, &coll_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Collection not found".to_string()))?;

    Ok(HttpResponse::Ok().json(collection.to_json()))
}

pub async fn update(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    body: web::Json<CollectionRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, coll_id) = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    Collection::update(&pool, &coll_id, &body.name).await?;

    let updated = Collection::find_by_uuid(&pool, &coll_id)
        .await?
        .ok_or_else(|| AppError::Internal("Collection disappeared".to_string()))?;

    Ok(HttpResponse::Ok().json(updated.to_json()))
}

pub async fn delete(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, coll_id) = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    Collection::delete(&pool, &coll_id).await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn get_users(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, coll_id) = path.into_inner();

    UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    let users: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT user_uuid, read_only, hide_passwords FROM users_collections WHERE collection_uuid = ?"
    )
    .bind(&coll_id)
    .fetch_all(pool.get_ref())
    .await?;

    let data: Vec<_> = users
        .iter()
        .map(|(user_uuid, read_only, hide_passwords)| {
            serde_json::json!({
                "Object": "collectionUser",
                "Id": user_uuid,
                "ReadOnly": read_only,
                "HidePasswords": hide_passwords,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "list",
        "Data": data,
        "ContinuationToken": null,
    })))
}

pub async fn set_users(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    body: web::Json<SetUsersRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, coll_id) = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    // Clear existing and re-add
    sqlx::query("DELETE FROM users_collections WHERE collection_uuid = ?")
        .bind(&coll_id)
        .execute(pool.get_ref())
        .await?;

    for entry in &body.users {
        Collection::add_user(
            &pool,
            &coll_id,
            &entry.id,
            entry.read_only.unwrap_or(false),
            entry.hide_passwords.unwrap_or(false),
        )
        .await?;
    }

    Ok(HttpResponse::Ok().finish())
}
