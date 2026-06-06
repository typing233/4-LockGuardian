use serde_json::Value;
use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Organization {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,
    pub plan_type: i32,
    pub key_: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserOrganization {
    pub uuid: String,
    pub user_uuid: String,
    pub org_uuid: String,
    pub access_all: bool,
    pub key_: Option<String>,
    pub status: i32,
    pub type_: i32,
    pub created_at: String,
    pub updated_at: String,
}

// OrgUserStatus
pub const ORG_USER_STATUS_INVITED: i32 = 0;
pub const ORG_USER_STATUS_ACCEPTED: i32 = 1;
pub const ORG_USER_STATUS_CONFIRMED: i32 = 2;

// OrgUserType
pub const ORG_USER_TYPE_OWNER: i32 = 0;
pub const ORG_USER_TYPE_ADMIN: i32 = 1;
pub const ORG_USER_TYPE_USER: i32 = 2;
pub const ORG_USER_TYPE_MANAGER: i32 = 3;

impl Organization {
    pub async fn create(
        pool: &SqlitePool,
        name: &str,
        billing_email: &str,
        key: Option<&str>,
    ) -> Result<Self, AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO organizations (uuid, name, billing_email, key_, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&uuid)
        .bind(name)
        .bind(billing_email)
        .bind(key)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            uuid,
            name: name.to_string(),
            billing_email: billing_email.to_string(),
            plan_type: 0,
            key_: key.map(String::from),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_uuid(pool: &SqlitePool, uuid: &str) -> Result<Option<Self>, AppError> {
        let org = sqlx::query_as::<_, Self>("SELECT * FROM organizations WHERE uuid = ?")
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
        Ok(org)
    }

    pub fn to_json(&self, user_org: &UserOrganization) -> Value {
        serde_json::json!({
            "Object": "profileOrganization",
            "Id": self.uuid,
            "Name": self.name,
            "UseGroups": false,
            "UseDirectory": false,
            "UseEvents": true,
            "UseTotp": true,
            "Use2fa": true,
            "UseApi": true,
            "UsePolicies": false,
            "UseSso": false,
            "UseKeyConnector": false,
            "UseResetPassword": false,
            "SelfHost": true,
            "UsersGetPremium": true,
            "Seats": 100,
            "MaxCollections": 100,
            "MaxStorageGb": null,
            "Key": user_org.key_,
            "Status": user_org.status,
            "Type": user_org.type_,
            "Enabled": true,
            "ProviderId": null,
            "ProviderName": null,
            "HasPublicAndPrivateKeys": self.key_.is_some(),
            "Identifier": null,
        })
    }
}

impl UserOrganization {
    pub async fn create(
        pool: &SqlitePool,
        user_uuid: &str,
        org_uuid: &str,
        type_: i32,
        status: i32,
        access_all: bool,
        key: Option<&str>,
    ) -> Result<Self, AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, type_, status, key_, access_all, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&uuid)
        .bind(user_uuid)
        .bind(org_uuid)
        .bind(type_)
        .bind(status)
        .bind(key)
        .bind(access_all)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            uuid,
            user_uuid: user_uuid.to_string(),
            org_uuid: org_uuid.to_string(),
            access_all,
            key_: key.map(String::from),
            status,
            type_,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_user(
        pool: &SqlitePool,
        user_uuid: &str,
    ) -> Result<Vec<Self>, AppError> {
        let orgs = sqlx::query_as::<_, Self>(
            "SELECT * FROM users_organizations WHERE user_uuid = ?",
        )
        .bind(user_uuid)
        .fetch_all(pool)
        .await?;
        Ok(orgs)
    }

    pub async fn find_by_org(pool: &SqlitePool, org_uuid: &str) -> Result<Vec<Self>, AppError> {
        let orgs =
            sqlx::query_as::<_, Self>("SELECT * FROM users_organizations WHERE org_uuid = ?")
                .bind(org_uuid)
                .fetch_all(pool)
                .await?;
        Ok(orgs)
    }

    pub async fn find_by_user_and_org(
        pool: &SqlitePool,
        user_uuid: &str,
        org_uuid: &str,
    ) -> Result<Option<Self>, AppError> {
        let org = sqlx::query_as::<_, Self>(
            "SELECT * FROM users_organizations WHERE user_uuid = ? AND org_uuid = ?",
        )
        .bind(user_uuid)
        .bind(org_uuid)
        .fetch_optional(pool)
        .await?;
        Ok(org)
    }

    pub async fn update_status(
        pool: &SqlitePool,
        uuid: &str,
        status: i32,
    ) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE users_organizations SET status = ?, updated_at = ? WHERE uuid = ?")
            .bind(status)
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn confirm(
        pool: &SqlitePool,
        uuid: &str,
        key: &str,
    ) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE users_organizations SET status = ?, key_ = ?, updated_at = ? WHERE uuid = ?")
            .bind(ORG_USER_STATUS_CONFIRMED)
            .bind(key)
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn delete(pool: &SqlitePool, uuid: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM users_organizations WHERE uuid = ?")
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }
}
