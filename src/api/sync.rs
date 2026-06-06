use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::cipher::Cipher;
use crate::models::collection::Collection;
use crate::models::folder::Folder;
use crate::models::organization::{Organization, UserOrganization};
use crate::models::user::User;

pub async fn sync(
    user: AuthenticatedUser,
    pool: web::Data<SqlitePool>,
    config: web::Data<AppConfig>,
) -> Result<HttpResponse, AppError> {
    let db_user = User::find_by_uuid(&pool, &user.uuid)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let folders = Folder::find_by_user(&pool, &user.uuid).await?;
    let ciphers = Cipher::find_by_user_including_deleted(&pool, &user.uuid).await?;
    let user_orgs = UserOrganization::find_by_user(&pool, &user.uuid).await?;
    let collections = Collection::find_by_user(&pool, &user.uuid).await?;

    // Build org ciphers
    let mut all_ciphers: Vec<serde_json::Value> = ciphers
        .iter()
        .map(|c| c.to_json(&config.domain))
        .collect();

    // Include org ciphers
    for uo in &user_orgs {
        if uo.status == 2 {
            // Confirmed
            let org_ciphers = Cipher::find_by_org(&pool, &uo.org_uuid).await?;
            for c in &org_ciphers {
                all_ciphers.push(c.to_json(&config.domain));
            }
        }
    }

    // Build orgs response
    let mut org_responses = Vec::new();
    for uo in &user_orgs {
        if let Some(org) = Organization::find_by_uuid(&pool, &uo.org_uuid).await? {
            org_responses.push(org.to_json(uo));
        }
    }

    let folder_json: Vec<_> = folders.iter().map(|f| f.to_json()).collect();
    let collection_json: Vec<_> = collections.iter().map(|c| c.to_json()).collect();

    let profile = serde_json::json!({
        "Object": "profile",
        "Id": db_user.uuid,
        "Name": db_user.name,
        "Email": db_user.email,
        "EmailVerified": db_user.email_verified,
        "Premium": db_user.premium,
        "MasterPasswordHint": null,
        "Culture": "en-US",
        "TwoFactorEnabled": false,
        "Key": db_user.key_,
        "PrivateKey": db_user.private_key,
        "SecurityStamp": db_user.security_stamp,
        "Organizations": org_responses,
        "Providers": [],
        "ForcePasswordReset": false,
        "AvatarColor": null,
        "CreationDate": db_user.created_at,
    });

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "Object": "sync",
        "Profile": profile,
        "Folders": folder_json,
        "Collections": collection_json,
        "Ciphers": all_ciphers,
        "Domains": {
            "Object": "domains",
            "EquivalentDomains": [],
            "GlobalEquivalentDomains": [],
        },
        "Policies": [],
        "Sends": [],
    })))
}
