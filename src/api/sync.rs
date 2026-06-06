use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;

use crate::auth::middleware::AuthenticatedUser;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::models::cipher::Cipher;
use crate::models::collection::Collection;
use crate::models::folder::Folder;
use crate::models::organization::{
    Organization, UserOrganization, ORG_USER_STATUS_CONFIRMED, ORG_USER_TYPE_ADMIN,
};
use crate::models::user::User;

#[derive(sqlx::FromRow)]
struct CipherCollectionPerm {
    cipher_uuid: String,
    read_only: bool,
    hide_passwords: bool,
}

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

    let mut all_ciphers: Vec<serde_json::Value> = ciphers
        .iter()
        .map(|c| c.to_json(&config.domain))
        .collect();

    // Include org ciphers with proper permission filtering
    for uo in &user_orgs {
        if uo.status != ORG_USER_STATUS_CONFIRMED {
            continue;
        }

        let org_ciphers = Cipher::find_by_org(&pool, &uo.org_uuid).await?;

        // Owner/Admin can see/edit all org ciphers
        if uo.type_ <= ORG_USER_TYPE_ADMIN {
            for c in &org_ciphers {
                all_ciphers.push(c.to_json(&config.domain));
            }
        } else if uo.access_all {
            // access_all grants read+write to all org ciphers
            for c in &org_ciphers {
                all_ciphers.push(c.to_json(&config.domain));
            }
        } else {
            // Only ciphers in collections the user has access to, with permission flags
            let perms: Vec<CipherCollectionPerm> = sqlx::query_as(
                "SELECT cc.cipher_uuid, uc.read_only, uc.hide_passwords
                 FROM ciphers_collections cc
                 INNER JOIN users_collections uc ON uc.collection_uuid = cc.collection_uuid
                 INNER JOIN ciphers ci ON ci.uuid = cc.cipher_uuid
                 WHERE uc.user_uuid = ? AND ci.organization_uuid = ?"
            )
            .bind(&user.uuid)
            .bind(&uo.org_uuid)
            .fetch_all(pool.get_ref())
            .await?;

            // Aggregate permissions per cipher: most permissive wins
            let mut cipher_perms: std::collections::HashMap<&str, (bool, bool)> =
                std::collections::HashMap::new();
            for p in &perms {
                let entry = cipher_perms.entry(p.cipher_uuid.as_str()).or_insert((true, true));
                // If any collection grants write (read_only=false), user can edit
                if !p.read_only {
                    entry.0 = false; // not read_only
                }
                // If any collection grants view_password (hide_passwords=false), user can view
                if !p.hide_passwords {
                    entry.1 = false; // not hide_passwords
                }
            }

            for c in &org_ciphers {
                if let Some(&(read_only, hide_passwords)) = cipher_perms.get(c.uuid.as_str()) {
                    let can_edit = !read_only;
                    let view_password = !hide_passwords;
                    all_ciphers.push(c.to_json_with_permissions(&config.domain, can_edit, view_password));
                }
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
