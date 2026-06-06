use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct Event {
    pub uuid: String,
    pub type_: i32,
    pub user_uuid: Option<String>,
    pub org_uuid: Option<String>,
    pub cipher_uuid: Option<String>,
    pub collection_uuid: Option<String>,
    pub acting_user_uuid: Option<String>,
    pub device_type: Option<i32>,
    pub ip_address: Option<String>,
    pub event_date: String,
}

// Event types (subset of Bitwarden's event types)
pub const EVENT_USER_LOGGED_IN: i32 = 1000;
pub const EVENT_USER_CHANGED_PASSWORD: i32 = 1001;
pub const EVENT_USER_ENABLED_2FA: i32 = 1002;
pub const EVENT_USER_DISABLED_2FA: i32 = 1003;
pub const EVENT_CIPHER_CREATED: i32 = 1100;
pub const EVENT_CIPHER_UPDATED: i32 = 1101;
pub const EVENT_CIPHER_DELETED: i32 = 1102;
pub const EVENT_CIPHER_RESTORED: i32 = 1104;
pub const EVENT_COLLECTION_CREATED: i32 = 1300;
pub const EVENT_ORG_USER_INVITED: i32 = 1400;
pub const EVENT_ORG_USER_CONFIRMED: i32 = 1401;
pub const EVENT_ORG_USER_REMOVED: i32 = 1402;

impl Event {
    pub async fn log(
        pool: &SqlitePool,
        type_: i32,
        user_uuid: Option<&str>,
        org_uuid: Option<&str>,
        cipher_uuid: Option<&str>,
        collection_uuid: Option<&str>,
        acting_user_uuid: Option<&str>,
        device_type: Option<i32>,
        ip_address: Option<&str>,
    ) -> Result<(), AppError> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

        sqlx::query(
            "INSERT INTO events (uuid, type_, user_uuid, org_uuid, cipher_uuid, collection_uuid, acting_user_uuid, device_type, ip_address, event_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&uuid)
        .bind(type_)
        .bind(user_uuid)
        .bind(org_uuid)
        .bind(cipher_uuid)
        .bind(collection_uuid)
        .bind(acting_user_uuid)
        .bind(device_type)
        .bind(ip_address)
        .bind(&now)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn find_by_user(
        pool: &SqlitePool,
        user_uuid: &str,
        start: Option<&str>,
        end: Option<&str>,
    ) -> Result<Vec<Self>, AppError> {
        let events = if let (Some(start), Some(end)) = (start, end) {
            sqlx::query_as::<_, Self>(
                "SELECT * FROM events WHERE acting_user_uuid = ? AND event_date >= ? AND event_date <= ? ORDER BY event_date DESC LIMIT 1000"
            )
            .bind(user_uuid)
            .bind(start)
            .bind(end)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as::<_, Self>(
                "SELECT * FROM events WHERE acting_user_uuid = ? ORDER BY event_date DESC LIMIT 1000"
            )
            .bind(user_uuid)
            .fetch_all(pool)
            .await?
        };
        Ok(events)
    }

    pub async fn find_by_org(
        pool: &SqlitePool,
        org_uuid: &str,
        start: Option<&str>,
        end: Option<&str>,
    ) -> Result<Vec<Self>, AppError> {
        let events = if let (Some(start), Some(end)) = (start, end) {
            sqlx::query_as::<_, Self>(
                "SELECT * FROM events WHERE org_uuid = ? AND event_date >= ? AND event_date <= ? ORDER BY event_date DESC LIMIT 1000"
            )
            .bind(org_uuid)
            .bind(start)
            .bind(end)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as::<_, Self>(
                "SELECT * FROM events WHERE org_uuid = ? ORDER BY event_date DESC LIMIT 1000",
            )
            .bind(org_uuid)
            .fetch_all(pool)
            .await?
        };
        Ok(events)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "Object": "event",
            "Type": self.type_,
            "UserId": self.user_uuid,
            "OrganizationId": self.org_uuid,
            "CipherId": self.cipher_uuid,
            "CollectionId": self.collection_uuid,
            "ActingUserId": self.acting_user_uuid,
            "DeviceType": self.device_type,
            "IpAddress": self.ip_address,
            "Date": self.event_date,
        })
    }
}
