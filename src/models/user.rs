use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub uuid: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub salt: String,
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    pub security_stamp: String,
    pub key_: Option<String>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub premium: bool,
    pub email_verified: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl User {
    pub async fn create(
        pool: &SqlitePool,
        email: &str,
        name: &str,
        password_hash: &str,
        salt: &str,
        kdf_type: i32,
        kdf_iterations: i32,
        kdf_memory: Option<i32>,
        kdf_parallelism: Option<i32>,
        key: Option<&str>,
        public_key: Option<&str>,
        private_key: Option<&str>,
    ) -> Result<Self, AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let security_stamp = crate::crypto::generate_security_stamp();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO users (uuid, email, name, password_hash, salt, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, key_, public_key, private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&uuid)
        .bind(email)
        .bind(name)
        .bind(password_hash)
        .bind(salt)
        .bind(kdf_type)
        .bind(kdf_iterations)
        .bind(kdf_memory)
        .bind(kdf_parallelism)
        .bind(&security_stamp)
        .bind(key)
        .bind(public_key)
        .bind(private_key)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            uuid,
            email: email.to_string(),
            name: name.to_string(),
            password_hash: password_hash.to_string(),
            salt: salt.to_string(),
            kdf_type,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
            security_stamp,
            key_: key.map(String::from),
            public_key: public_key.map(String::from),
            private_key: private_key.map(String::from),
            premium: true,
            email_verified: true,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_email(pool: &SqlitePool, email: &str) -> Result<Option<Self>, AppError> {
        let user = sqlx::query_as::<_, Self>("SELECT * FROM users WHERE email = ? COLLATE NOCASE")
            .bind(email)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    pub async fn find_by_uuid(pool: &SqlitePool, uuid: &str) -> Result<Option<Self>, AppError> {
        let user = sqlx::query_as::<_, Self>("SELECT * FROM users WHERE uuid = ?")
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    pub async fn update_security_stamp(pool: &SqlitePool, uuid: &str) -> Result<String, AppError> {
        let new_stamp = crate::crypto::generate_security_stamp();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE users SET security_stamp = ?, updated_at = ? WHERE uuid = ?")
            .bind(&new_stamp)
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(new_stamp)
    }

    pub async fn update_keys(
        pool: &SqlitePool,
        uuid: &str,
        key: &str,
        public_key: &str,
        private_key: &str,
    ) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query(
            "UPDATE users SET key_ = ?, public_key = ?, private_key = ?, updated_at = ? WHERE uuid = ?",
        )
        .bind(key)
        .bind(public_key)
        .bind(private_key)
        .bind(&now)
        .bind(uuid)
        .execute(pool)
        .await?;
        Ok(())
    }
}
