use serde_json::Value;
use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Folder {
    pub uuid: String,
    pub user_uuid: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Folder {
    pub async fn create(
        pool: &SqlitePool,
        user_uuid: &str,
        name: &str,
    ) -> Result<Self, AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO folders (uuid, user_uuid, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&uuid)
        .bind(user_uuid)
        .bind(name)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            uuid,
            user_uuid: user_uuid.to_string(),
            name: name.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_user(pool: &SqlitePool, user_uuid: &str) -> Result<Vec<Self>, AppError> {
        let folders = sqlx::query_as::<_, Self>("SELECT * FROM folders WHERE user_uuid = ?")
            .bind(user_uuid)
            .fetch_all(pool)
            .await?;
        Ok(folders)
    }

    pub async fn find_by_uuid(pool: &SqlitePool, uuid: &str) -> Result<Option<Self>, AppError> {
        let folder = sqlx::query_as::<_, Self>("SELECT * FROM folders WHERE uuid = ?")
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
        Ok(folder)
    }

    pub async fn update(pool: &SqlitePool, uuid: &str, name: &str) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE folders SET name = ?, updated_at = ? WHERE uuid = ?")
            .bind(name)
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn delete(pool: &SqlitePool, uuid: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM folders WHERE uuid = ?")
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "Object": "folder",
            "Id": self.uuid,
            "Name": self.name,
            "RevisionDate": self.updated_at,
        })
    }
}
