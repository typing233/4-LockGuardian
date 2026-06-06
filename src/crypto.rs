use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey,
};
use std::fs;
use std::path::Path;

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub struct RsaKeys {
    pub private_key: RsaPrivateKey,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
}

impl RsaKeys {
    pub fn load_or_generate(path: &str) -> Self {
        let private_key = if Path::new(path).exists() {
            let pem = fs::read_to_string(path).expect("Failed to read RSA key file");
            RsaPrivateKey::from_pkcs8_pem(&pem).expect("Failed to parse RSA key")
        } else {
            let mut rng = rand::thread_rng();
            let key =
                RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent).ok();
            }
            let pem = key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("Failed to encode RSA key");
            fs::write(path, pem.as_bytes()).expect("Failed to write RSA key file");
            key
        };

        let private_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Failed to encode private key");
        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("Failed to encode public key");

        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
                .expect("Failed to create encoding key");
        let decoding_key =
            jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes())
                .expect("Failed to create decoding key");

        Self {
            private_key,
            encoding_key,
            decoding_key,
        }
    }
}

pub fn generate_security_stamp() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn generate_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    data_encoding::BASE64URL_NOPAD.encode(&bytes)
}
