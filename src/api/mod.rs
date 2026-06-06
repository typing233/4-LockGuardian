pub mod accounts;
pub mod attachments;
pub mod ciphers;
pub mod collections;
pub mod folders;
pub mod identity;
pub mod organizations;
pub mod sync;
pub mod two_factor;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/identity")
            .route("/connect/token", web::post().to(identity::login)),
    )
    .service(
        web::scope("/api")
            .route("/accounts/register", web::post().to(accounts::register))
            .route("/accounts/prelogin", web::post().to(accounts::prelogin))
            .route("/accounts/profile", web::get().to(accounts::profile))
            .route("/accounts/profile", web::put().to(accounts::update_profile))
            .route("/accounts/keys", web::post().to(accounts::post_keys))
            .route("/accounts/revision-date", web::get().to(accounts::revision_date))
            .route("/accounts/export", web::post().to(accounts::export_vault))
            .route("/sync", web::get().to(sync::sync))
            // Ciphers
            .route("/ciphers", web::get().to(ciphers::list))
            .route("/ciphers", web::post().to(ciphers::create))
            .route("/ciphers/{uuid}", web::get().to(ciphers::get))
            .route("/ciphers/{uuid}", web::put().to(ciphers::update))
            .route("/ciphers/{uuid}", web::post().to(ciphers::update))
            .route("/ciphers/{uuid}/delete", web::post().to(ciphers::soft_delete))
            .route("/ciphers/{uuid}/delete", web::put().to(ciphers::soft_delete))
            .route("/ciphers/{uuid}", web::delete().to(ciphers::hard_delete))
            .route("/ciphers/{uuid}/restore", web::put().to(ciphers::restore))
            .route("/ciphers/delete", web::post().to(ciphers::bulk_soft_delete))
            .route("/ciphers/restore", web::put().to(ciphers::bulk_restore))
            // Folders
            .route("/folders", web::get().to(folders::list))
            .route("/folders", web::post().to(folders::create))
            .route("/folders/{uuid}", web::get().to(folders::get))
            .route("/folders/{uuid}", web::put().to(folders::update))
            .route("/folders/{uuid}", web::post().to(folders::update))
            .route("/folders/{uuid}", web::delete().to(folders::delete))
            // Organizations
            .route("/organizations", web::get().to(organizations::list))
            .route("/organizations", web::post().to(organizations::create))
            .route("/organizations/{org_id}", web::get().to(organizations::get))
            .route("/organizations/{org_id}", web::delete().to(organizations::delete))
            .route("/organizations/{org_id}/users", web::get().to(organizations::list_users))
            .route("/organizations/{org_id}/users/invite", web::post().to(organizations::invite_user))
            .route("/organizations/{org_id}/users/{user_org_id}/confirm", web::post().to(organizations::confirm_user))
            .route("/organizations/{org_id}/users/{user_org_id}", web::delete().to(organizations::remove_user))
            // Collections
            .route("/organizations/{org_id}/collections", web::get().to(collections::list))
            .route("/organizations/{org_id}/collections", web::post().to(collections::create))
            .route("/organizations/{org_id}/collections/{coll_id}", web::get().to(collections::get))
            .route("/organizations/{org_id}/collections/{coll_id}", web::put().to(collections::update))
            .route("/organizations/{org_id}/collections/{coll_id}", web::delete().to(collections::delete))
            .route("/organizations/{org_id}/collections/{coll_id}/users", web::get().to(collections::get_users))
            .route("/organizations/{org_id}/collections/{coll_id}/users", web::put().to(collections::set_users))
            // Two-Factor
            .route("/two-factor/get-authenticator", web::post().to(two_factor::get_authenticator))
            .route("/two-factor/authenticator", web::post().to(two_factor::activate_authenticator))
            .route("/two-factor/disable", web::post().to(two_factor::disable))
            .route("/two-factor/get-recover", web::post().to(two_factor::get_recover))
            .route("/two-factor/recover", web::post().to(two_factor::recover))
            // Attachments
            .route("/ciphers/{uuid}/attachment", web::post().to(attachments::upload))
            .route("/ciphers/{uuid}/attachment/{attachment_id}", web::delete().to(attachments::delete_attachment))
            // Events
            .route("/events/collect", web::post().to(event_collect))
            // Devices
            .route("/devices/identifier/{identifier}/clear-token", web::post().to(clear_push_token))
            .route("/devices/identifier/{identifier}/token", web::put().to(update_push_token)),
    )
    .route("/alive", web::get().to(alive))
    .route("/now", web::get().to(alive))
    .route("/attachments/{cipher_id}/{attachment_id}", web::get().to(attachments::download));
}

async fn alive() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}

async fn event_collect() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}

async fn clear_push_token() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}

async fn update_push_token() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}
