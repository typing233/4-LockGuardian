use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::error::AppError;
use crate::models::organization::*;
use crate::models::user::User;

#[derive(Deserialize)]
pub struct CreateOrgRequest {
    #[serde(rename = "name", alias = "Name")]
    pub name: String,
    #[serde(rename = "billingEmail", alias = "BillingEmail")]
    pub billing_email: String,
    #[serde(rename = "key", alias = "Key")]
    pub key: Option<String>,
    #[serde(rename = "collectionName", alias = "CollectionName")]
    pub collection_name: Option<String>,
    #[serde(rename = "keys", alias = "Keys")]
    pub keys: Option<OrgKeysRequest>,
}

#[derive(Deserialize)]
pub struct OrgKeysRequest {
    #[serde(rename = "publicKey", alias = "PublicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "encryptedPrivateKey", alias = "EncryptedPrivateKey")]
    pub encrypted_private_key: Option<String>,
}

#[derive(Deserialize)]
pub struct InviteRequest {
    #[serde(rename = "emails", alias = "Emails")]
    pub emails: Vec<String>,
    #[serde(rename = "type", alias = "Type")]
    pub type_: Option<i32>,
    #[serde(rename = "accessAll", alias = "AccessAll")]
    pub access_all: Option<bool>,
    #[serde(rename = "collections", alias = "Collections")]
    pub collections: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
pub struct ConfirmRequest {
    #[serde(rename = "key", alias = "Key")]
    pub key: String,
}

pub async fn list(
    user: AuthenticatedUser,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let user_orgs = UserOrganization::find_by_user(&pool, &user.uuid).await?;
    let mut data = Vec::new();

    for uo in &user_orgs {
        if let Some(org) = Organization::find_by_uuid(&pool, &uo.org_uuid).await? {
            data.push(org.to_json(uo));
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "list",
        "Data": data,
        "ContinuationToken": null,
    })))
}

pub async fn create(
    user: AuthenticatedUser,
    body: web::Json<CreateOrgRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org = Organization::create(&pool, &body.name, &body.billing_email, body.key.as_deref())
        .await?;

    // Add creator as owner
    let uo = UserOrganization::create(
        &pool,
        &user.uuid,
        &org.uuid,
        ORG_USER_TYPE_OWNER,
        ORG_USER_STATUS_CONFIRMED,
        body.key.as_deref(),
    )
    .await?;

    // Create default collection if requested
    if let Some(collection_name) = &body.collection_name {
        if !collection_name.is_empty() {
            crate::models::collection::Collection::create(&pool, &org.uuid, collection_name)
                .await?;
        }
    }

    Ok(HttpResponse::Ok().json(org.to_json(&uo)))
}

pub async fn get(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org_id = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = Organization::find_by_uuid(&pool, &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    Ok(HttpResponse::Ok().json(org.to_json(&uo)))
}

pub async fn delete(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org_id = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ != ORG_USER_TYPE_OWNER {
        return Err(AppError::Forbidden("Only owners can delete organizations".to_string()));
    }

    sqlx::query("DELETE FROM organizations WHERE uuid = ?")
        .bind(&org_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn list_users(
    user: AuthenticatedUser,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org_id = path.into_inner();

    // Verify user is member
    UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    let members = UserOrganization::find_by_org(&pool, &org_id).await?;
    let mut data = Vec::new();

    for m in &members {
        let member_user = User::find_by_uuid(&pool, &m.user_uuid).await?;
        let email = member_user.as_ref().map(|u| u.email.as_str()).unwrap_or("");
        let name = member_user.as_ref().map(|u| u.name.as_str()).unwrap_or("");

        data.push(serde_json::json!({
            "Object": "organizationUserDetails",
            "Id": m.uuid,
            "UserId": m.user_uuid,
            "Name": name,
            "Email": email,
            "Status": m.status,
            "Type": m.type_,
            "AccessAll": m.access_all,
            "TwoFactorEnabled": false,
            "ResetPasswordEnrolled": false,
        }));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "list",
        "Data": data,
        "ContinuationToken": null,
    })))
}

pub async fn invite_user(
    user: AuthenticatedUser,
    path: web::Path<String>,
    body: web::Json<InviteRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let org_id = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    // Must be admin or owner
    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    let invite_type = body.type_.unwrap_or(ORG_USER_TYPE_USER);

    for email in &body.emails {
        if let Some(invited_user) = User::find_by_email(&pool, email).await? {
            // Check not already member
            if UserOrganization::find_by_user_and_org(&pool, &invited_user.uuid, &org_id)
                .await?
                .is_none()
            {
                UserOrganization::create(
                    &pool,
                    &invited_user.uuid,
                    &org_id,
                    invite_type,
                    ORG_USER_STATUS_INVITED,
                    None,
                )
                .await?;
            }
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub async fn confirm_user(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    body: web::Json<ConfirmRequest>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, user_org_id) = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    UserOrganization::confirm(&pool, &user_org_id, &body.key).await?;

    Ok(HttpResponse::Ok().finish())
}

pub async fn remove_user(
    user: AuthenticatedUser,
    path: web::Path<(String, String)>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, AppError> {
    let (org_id, user_org_id) = path.into_inner();

    let uo = UserOrganization::find_by_user_and_org(&pool, &user.uuid, &org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("Access denied".to_string()))?;

    if uo.type_ > ORG_USER_TYPE_ADMIN {
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }

    UserOrganization::delete(&pool, &user_org_id).await?;

    Ok(HttpResponse::Ok().finish())
}
