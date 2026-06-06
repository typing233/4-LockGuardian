use serde_json::Value;
use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Collection {
    pub uuid: String,
    pub org_uuid: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserCollection {
    pub user_uuid: String,
    pub collection_uuid: String,
    pub read_only: bool,
    pub hide_passwords: bool,
}

impl Collection {
    pub async fn create(
        pool: &SqlitePool,
        org_uuid: &str,
        name: &str,
    ) -> Result<Self, AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO collections (uuid, org_uuid, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&uuid)
        .bind(org_uuid)
        .bind(name)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            uuid,
            org_uuid: org_uuid.to_string(),
            name: name.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_org(pool: &SqlitePool, org_uuid: &str) -> Result<Vec<Self>, AppError> {
        let collections =
            sqlx::query_as::<_, Self>("SELECT * FROM collections WHERE org_uuid = ?")
                .bind(org_uuid)
                .fetch_all(pool)
                .await?;
        Ok(collections)
    }

    pub async fn find_by_uuid(pool: &SqlitePool, uuid: &str) -> Result<Option<Self>, AppError> {
        let collection = sqlx::query_as::<_, Self>("SELECT * FROM collections WHERE uuid = ?")
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
        Ok(collection)
    }

    pub async fn find_by_user(pool: &SqlitePool, user_uuid: &str) -> Result<Vec<Self>, AppError> {
        let collections = sqlx::query_as::<_, Self>(
            "SELECT c.* FROM collections c
             INNER JOIN users_collections uc ON uc.collection_uuid = c.uuid
             WHERE uc.user_uuid = ?
             UNION
             SELECT c.* FROM collections c
             INNER JOIN users_organizations uo ON uo.org_uuid = c.org_uuid
             WHERE uo.user_uuid = ? AND uo.access_all = 1 AND uo.status = 2",
        )
        .bind(user_uuid)
        .bind(user_uuid)
        .fetch_all(pool)
        .await?;
        Ok(collections)
    }

    pub async fn update(pool: &SqlitePool, uuid: &str, name: &str) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE collections SET name = ?, updated_at = ? WHERE uuid = ?")
            .bind(name)
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn delete(pool: &SqlitePool, uuid: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM collections WHERE uuid = ?")
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn add_user(
        pool: &SqlitePool,
        collection_uuid: &str,
        user_uuid: &str,
        read_only: bool,
        hide_passwords: bool,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT OR REPLACE INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords) VALUES (?, ?, ?, ?)"
        )
        .bind(user_uuid)
        .bind(collection_uuid)
        .bind(read_only)
        .bind(hide_passwords)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn remove_user(
        pool: &SqlitePool,
        collection_uuid: &str,
        user_uuid: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "DELETE FROM users_collections WHERE user_uuid = ? AND collection_uuid = ?",
        )
        .bind(user_uuid)
        .bind(collection_uuid)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn add_cipher(
        pool: &SqlitePool,
        collection_uuid: &str,
        cipher_uuid: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT OR IGNORE INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES (?, ?)",
        )
        .bind(cipher_uuid)
        .bind(collection_uuid)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn get_cipher_collection_ids(
        pool: &SqlitePool,
        cipher_uuid: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT collection_uuid FROM ciphers_collections WHERE cipher_uuid = ?",
        )
        .bind(cipher_uuid)
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "Object": "collection",
            "Id": self.uuid,
            "OrganizationId": self.org_uuid,
            "Name": self.name,
            "ExternalId": null,
            "ReadOnly": false,
            "HidePasswords": false,
        })
    }
}
