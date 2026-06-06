use std::env;

pub struct AppConfig {
    pub database_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub domain: String,
    pub rsa_key_path: String,
    pub signups_allowed: bool,
    pub log_level: String,
    pub attachments_folder: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./data/lockguardian.db?mode=rwc".to_string()),
            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: env::var("SERVER_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            domain: env::var("DOMAIN").unwrap_or_else(|_| "http://localhost:8080".to_string()),
            rsa_key_path: env::var("RSA_KEY_PATH")
                .unwrap_or_else(|_| "./data/rsa_key.pem".to_string()),
            signups_allowed: env::var("SIGNUPS_ALLOWED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            attachments_folder: env::var("ATTACHMENTS_FOLDER")
                .unwrap_or_else(|_| "./data/attachments".to_string()),
        }
    }
}
