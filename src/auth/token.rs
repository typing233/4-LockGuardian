use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub name: String,
    pub premium: bool,
    pub iss_domain: String,
    pub sstamp: String,
    pub device: String,
    pub scope: Vec<String>,
    pub amr: Vec<String>,
}

pub fn generate_access_token(
    user_uuid: &str,
    email: &str,
    name: &str,
    premium: bool,
    security_stamp: &str,
    device_uuid: &str,
    domain: &str,
    encoding_key: &EncodingKey,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let claims = Claims {
        nbf: now.timestamp(),
        exp: (now + Duration::hours(2)).timestamp(),
        iss: format!("{}|lockguardian", domain),
        sub: user_uuid.to_string(),
        email: email.to_string(),
        name: name.to_string(),
        premium,
        iss_domain: domain.to_string(),
        sstamp: security_stamp.to_string(),
        device: device_uuid.to_string(),
        scope: vec!["api".to_string(), "offline_access".to_string()],
        amr: vec!["Application".to_string()],
    };

    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, encoding_key)
}

pub fn validate_token(
    token: &str,
    decoding_key: &DecodingKey,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_issuer(&[] as &[&str]);
    validation.insecure_disable_signature_validation();

    // Actually validate properly
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    // Don't validate issuer since it contains the domain
    validation.set_required_spec_claims(&["exp", "sub"]);

    let token_data = decode::<Claims>(token, decoding_key, &validation)?;
    Ok(token_data.claims)
}
