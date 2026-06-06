use serde_json::Value;
use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Cipher {
    pub uuid: String,
    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub type_: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,
    pub data: String,
    pub favorite: bool,
    pub reprompt: i32,
    pub folder_uuid: Option<String>,
    pub deleted_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Cipher {
    pub async fn create(
        pool: &SqlitePool,
        user_uuid: Option<&str>,
        org_uuid: Option<&str>,
        type_: i32,
        name: &str,
        notes: Option<&str>,
        fields: Option<&str>,
        data: &str,
        favorite: bool,
        reprompt: i32,
        folder_uuid: Option<&str>,
    ) -> Result<Self, AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO ciphers (uuid, user_uuid, organization_uuid, type_, name, notes, fields, data, favorite, reprompt, folder_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&uuid)
        .bind(user_uuid)
        .bind(org_uuid)
        .bind(type_)
        .bind(name)
        .bind(notes)
        .bind(fields)
        .bind(data)
        .bind(favorite)
        .bind(reprompt)
        .bind(folder_uuid)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Self {
            uuid,
            user_uuid: user_uuid.map(String::from),
            organization_uuid: org_uuid.map(String::from),
            type_,
            name: name.to_string(),
            notes: notes.map(String::from),
            fields: fields.map(String::from),
            data: data.to_string(),
            favorite,
            reprompt,
            folder_uuid: folder_uuid.map(String::from),
            deleted_at: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn find_by_user(pool: &SqlitePool, user_uuid: &str) -> Result<Vec<Self>, AppError> {
        let ciphers = sqlx::query_as::<_, Self>(
            "SELECT * FROM ciphers WHERE user_uuid = ? AND deleted_at IS NULL",
        )
        .bind(user_uuid)
        .fetch_all(pool)
        .await?;
        Ok(ciphers)
    }

    pub async fn find_by_user_including_deleted(
        pool: &SqlitePool,
        user_uuid: &str,
    ) -> Result<Vec<Self>, AppError> {
        let ciphers = sqlx::query_as::<_, Self>("SELECT * FROM ciphers WHERE user_uuid = ?")
            .bind(user_uuid)
            .fetch_all(pool)
            .await?;
        Ok(ciphers)
    }

    pub async fn find_by_org(pool: &SqlitePool, org_uuid: &str) -> Result<Vec<Self>, AppError> {
        let ciphers = sqlx::query_as::<_, Self>(
            "SELECT * FROM ciphers WHERE organization_uuid = ? AND deleted_at IS NULL",
        )
        .bind(org_uuid)
        .fetch_all(pool)
        .await?;
        Ok(ciphers)
    }

    pub async fn find_by_uuid(pool: &SqlitePool, uuid: &str) -> Result<Option<Self>, AppError> {
        let cipher = sqlx::query_as::<_, Self>("SELECT * FROM ciphers WHERE uuid = ?")
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
        Ok(cipher)
    }

    pub async fn update(
        pool: &SqlitePool,
        uuid: &str,
        name: &str,
        notes: Option<&str>,
        fields: Option<&str>,
        data: &str,
        favorite: bool,
        reprompt: i32,
        folder_uuid: Option<&str>,
    ) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query(
            "UPDATE ciphers SET name = ?, notes = ?, fields = ?, data = ?, favorite = ?, reprompt = ?, folder_uuid = ?, updated_at = ? WHERE uuid = ?"
        )
        .bind(name)
        .bind(notes)
        .bind(fields)
        .bind(data)
        .bind(favorite)
        .bind(reprompt)
        .bind(folder_uuid)
        .bind(&now)
        .bind(uuid)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn soft_delete(pool: &SqlitePool, uuid: &str) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE ciphers SET deleted_at = ?, updated_at = ? WHERE uuid = ?")
            .bind(&now)
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn restore(pool: &SqlitePool, uuid: &str) -> Result<(), AppError> {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        sqlx::query("UPDATE ciphers SET deleted_at = NULL, updated_at = ? WHERE uuid = ?")
            .bind(&now)
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn hard_delete(pool: &SqlitePool, uuid: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM ciphers WHERE uuid = ?")
            .bind(uuid)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub fn to_json(&self, domain: &str) -> Value {
        self.to_json_with_permissions(domain, true, true)
    }

    pub fn to_json_with_permissions(&self, domain: &str, can_edit: bool, view_password: bool) -> Value {
        let data: Value = serde_json::from_str(&self.data).unwrap_or(Value::Null);
        let fields: Option<Value> = self
            .fields
            .as_ref()
            .and_then(|f| serde_json::from_str(f).ok());

        let type_field = match self.type_ {
            1 => "Login",
            2 => "SecureNote",
            3 => "Card",
            4 => "Identity",
            _ => "Login",
        };

        let (data_out, type_data_out) = if view_password {
            (data.clone(), data)
        } else {
            (Self::redact_passwords(&data, self.type_), Self::redact_passwords(&data, self.type_))
        };

        let name = if view_password {
            self.name.clone()
        } else {
            self.name.clone()
        };

        serde_json::json!({
            "Object": "cipher",
            "Id": self.uuid,
            "OrganizationId": self.organization_uuid,
            "FolderId": self.folder_uuid,
            "Type": self.type_,
            "Name": name,
            "Notes": self.notes,
            "Fields": fields,
            type_field: type_data_out,
            "Data": data_out,
            "Favorite": self.favorite,
            "Reprompt": self.reprompt,
            "OrganizationUseTotp": false,
            "RevisionDate": self.updated_at,
            "CreationDate": self.created_at,
            "DeletedDate": self.deleted_at,
            "Attachments": null,
            "CollectionIds": [],
            "Edit": can_edit,
            "ViewPassword": view_password,
        })
    }

    fn redact_passwords(data: &Value, type_: i32) -> Value {
        let mut d = data.clone();
        if type_ == 1 {
            // Login type - redact password and totp
            if let Some(obj) = d.as_object_mut() {
                if obj.contains_key("password") || obj.contains_key("Password") {
                    obj.insert("Password".to_string(), Value::Null);
                    obj.remove("password");
                }
                if obj.contains_key("totp") || obj.contains_key("Totp") {
                    obj.insert("Totp".to_string(), Value::Null);
                    obj.remove("totp");
                }
            }
        } else if type_ == 3 {
            // Card type - redact code and number
            if let Some(obj) = d.as_object_mut() {
                if obj.contains_key("code") || obj.contains_key("Code") {
                    obj.insert("Code".to_string(), Value::Null);
                    obj.remove("code");
                }
                if obj.contains_key("number") || obj.contains_key("Number") {
                    obj.insert("Number".to_string(), Value::Null);
                    obj.remove("number");
                }
            }
        }
        d
    }
}
