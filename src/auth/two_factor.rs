use totp_rs::{Algorithm, Secret, TOTP};

pub fn verify_totp(secret: &str, code: &str) -> bool {
    let secret_bytes = match data_encoding::BASE32.decode(secret.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, String::new()) {
        Ok(t) => t,
        Err(_) => return false,
    };

    totp.check_current(code).unwrap_or(false)
}

pub fn generate_totp_secret() -> String {
    let secret = Secret::generate_secret();
    secret.to_encoded().to_string()
}

pub fn get_totp_uri(secret: &str, email: &str, issuer: &str) -> Option<String> {
    let secret_bytes = data_encoding::BASE32.decode(secret.as_bytes()).ok()?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        email.to_string(),
    )
    .ok()?;
    Some(totp.get_url())
}
