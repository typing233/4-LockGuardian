use serde_json::Value;
use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Attachment {
    pub id: String,
    pub cipher_uuid: String,
    pub file_name: String,
    pub file_size: i64,
    pub key_: Option<String>,
    pub created_at: String,
}

impl Attachment {
    pub async fn create(
        pool: &SqlitePool,
        cipher_uuid: &str,
        file_name: &str,
        file_size: i64,
        key: Option<&str>,
    ) -> Result<Self, AppError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO attachments (id, cipher_uuid, file_name, file_size, key_, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(cipher_uuid)
        .bind(file_name)
        .bind(file_size)
        .bind(key)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            id,
            cipher_uuid: cipher_uuid.to_string(),
            file_name: file_name.to_string(),
            file_size,
            key_: key.map(String::from),
            created_at: now,
        })
    }

    pub async fn find_by_cipher(
        pool: &SqlitePool,
        cipher_uuid: &str,
    ) -> Result<Vec<Self>, AppError> {
        let attachments =
            sqlx::query_as::<_, Self>("SELECT * FROM attachments WHERE cipher_uuid = ?")
                .bind(cipher_uuid)
                .fetch_all(pool)
                .await?;
        Ok(attachments)
    }

    pub async fn find_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Self>, AppError> {
        let attachment = sqlx::query_as::<_, Self>("SELECT * FROM attachments WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(attachment)
    }

    pub async fn delete(pool: &SqlitePool, id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM attachments WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub fn to_json(&self, domain: &str) -> Value {
        serde_json::json!({
            "Object": "attachment",
            "Id": self.id,
            "Url": format!("{}/attachments/{}/{}", domain, self.cipher_uuid, self.id),
            "FileName": self.file_name,
            "Size": self.file_size.to_string(),
            "SizeName": format_size(self.file_size),
            "Key": self.key_,
        })
    }
}

fn format_size(bytes: i64) -> String {
    if bytes < 1024 {
        format!("{} Bytes", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
