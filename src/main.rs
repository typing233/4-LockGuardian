mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod models;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let cfg = config::AppConfig::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level)),
        )
        .init();

    tracing::info!("Starting LockGuardian server");

    // Ensure data directories exist
    std::fs::create_dir_all("./data").ok();
    std::fs::create_dir_all(&cfg.attachments_folder).ok();

    let pool = db::create_pool(&cfg.database_url).await;
    db::run_migrations(&pool).await;

    let rsa_keys = Arc::new(crypto::RsaKeys::load_or_generate(&cfg.rsa_key_path));

    let bind_addr = format!("{}:{}", cfg.server_host, cfg.server_port);
    tracing::info!("Listening on {}", bind_addr);
    tracing::info!("Domain: {}", cfg.domain);

    let config_data = web::Data::new(cfg);
    let pool_data = web::Data::new(pool);
    let rsa_data = web::Data::new(rsa_keys);

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .wrap(tracing_actix_web::TracingLogger::default())
            .app_data(config_data.clone())
            .app_data(pool_data.clone())
            .app_data(rsa_data.clone())
            .configure(api::configure)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
