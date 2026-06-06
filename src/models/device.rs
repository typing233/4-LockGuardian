use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Device {
    pub uuid: String,
    pub user_uuid: String,
    pub name: String,
    pub type_: i32,
    pub push_token: Option<String>,
    pub refresh_token: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Device {
    pub async fn create_or_update(
        pool: &SqlitePool,
        user_uuid: &str,
        device_id: &str,
        device_name: &str,
        device_type: i32,
    ) -> Result<Self, AppError> {
        let refresh_token = crate::crypto::generate_token();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        // Try to find existing device
        let existing: Option<Device> =
            sqlx::query_as("SELECT * FROM devices WHERE uuid = ? AND user_uuid = ?")
                .bind(device_id)
                .bind(user_uuid)
                .fetch_optional(pool)
                .await?;

        if existing.is_some() {
            sqlx::query(
                "UPDATE devices SET refresh_token = ?, name = ?, updated_at = ? WHERE uuid = ?",
            )
            .bind(&refresh_token)
            .bind(device_name)
            .bind(&now)
            .bind(device_id)
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO devices (uuid, user_uuid, name, type_, refresh_token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(device_id)
            .bind(user_uuid)
            .bind(device_name)
            .bind(device_type)
            .bind(&refresh_token)
            .bind(&now)
            .bind(&now)
            .execute(pool)
            .await?;
        }

        Ok(Self {
            uuid: device_id.to_string(),
            user_uuid: user_uuid.to_string(),
            name: device_name.to_string(),
            type_: device_type,
            push_token: None,
            refresh_token,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_refresh_token(
        pool: &SqlitePool,
        refresh_token: &str,
    ) -> Result<Option<Self>, AppError> {
        let device =
            sqlx::query_as::<_, Self>("SELECT * FROM devices WHERE refresh_token = ?")
                .bind(refresh_token)
                .fetch_optional(pool)
                .await?;
        Ok(device)
    }

    pub async fn update_push_token(
        pool: &SqlitePool,
        device_uuid: &str,
        push_token: &str,
    ) -> Result<(), AppError> {
        sqlx::query("UPDATE devices SET push_token = ? WHERE uuid = ?")
            .bind(push_token)
            .bind(device_uuid)
            .execute(pool)
            .await?;
        Ok(())
    }
}
