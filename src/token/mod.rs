use crate::redis::{get_from_redis, save_to_redis};
use chrono::Utc;
use colored::Colorize;
use derive_more::Display;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use redis::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use uuid::Uuid;

const ISSUER: &'static str = "http://librevpn.net";

lazy_static! {
    static ref EDDSA_VALIDATION: Validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    static ref EDDSA_JWT_HEADER: Header = Header::new(jsonwebtoken::Algorithm::EdDSA);
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenDetails {
    pub token: String,
    pub token_uuid: Uuid,
    pub user_id: Uuid,
    pub expires_in: i64,
    pub fingerprint: Option<String>,
}

/// Claims of refresh and access tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    // subject (user's UUID)
    pub sub: String,

    // issued at (UNIX timestamp)
    pub iat: i64,

    // not before (UNIX timestamp)
    pub nbf: i64,

    // expiry time (UNIX timestamp)
    pub exp: i64,

    // issuer (Who issued the token)
    pub iss: String,

    // token UUID (needed for identifying tokens in Redis db)
    pub jti: Uuid,

    pub fingerprint: Option<String>,
}

#[derive(Debug, Display)]
pub struct JwtError(String);

impl Error for JwtError {}

impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

impl From<uuid::Error> for JwtError {
    fn from(value: uuid::Error) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

/// function to generate jwt token
/// sub: user_id
/// exp: current time + ttl
/// signed with provided encoding key
pub fn generate_jwt_token(
    user_id: &Uuid,
    ttl: i64,
    encoding_key: &EncodingKey,
    fingerprint: Option<String>,
) -> Result<TokenDetails, JwtError> {
    // current time
    let now = chrono::Utc::now();

    let jti = Uuid::new_v4();

    let exp = (now + chrono::Duration::minutes(ttl)).timestamp();

    let claims = TokenClaims {
        sub: user_id.to_string(),
        exp,
        iat: now.timestamp(),
        nbf: now.timestamp(),
        iss: ISSUER.to_string(),
        jti,
        fingerprint: fingerprint.clone(),
    };

    let token = jsonwebtoken::encode(&EDDSA_JWT_HEADER, &claims, encoding_key)?;

    let token_details = TokenDetails {
        user_id: *user_id,
        // token UUID (to identify it in Redis database)
        token_uuid: jti,
        // current time + provided ttl (time to live)
        expires_in: exp,
        token,
        fingerprint,
    };

    Ok(token_details)
}

/// function allows for JWT authentication using the public keys.
/// It verifies the JWT using the key to extract the corresponding payload.
/// The extracted payload is then used to
/// construct the TokenDetails struct, which is returned by the function.
pub fn verify_jwt_token(decoding_key: &DecodingKey, token: &str) -> Result<TokenDetails, JwtError> {
    debug!("verifying token: {}", token);
    let decoded = jsonwebtoken::decode::<TokenClaims>(token, decoding_key, &EDDSA_VALIDATION)?;

    debug!("decoded jwt: {:?}", decoded);

    let user_id = Uuid::parse_str(decoded.claims.sub.as_str())?;

    debug!("{}", user_id);

    let token_uuid = decoded.claims.jti;
    let token_expiry = decoded.claims.exp;
    let fingerprint = decoded.claims.fingerprint;

    Ok(TokenDetails {
        token: token.to_string(),
        token_uuid,
        user_id,
        expires_in: token_expiry,
        fingerprint,
    })
}

/// adds token to the black list (Redis db)
pub async fn blacklist_token(redis_client: &Client, token_details: &TokenDetails) {
    let exp = token_details.expires_in - Utc::now().timestamp();

    // it can only happen if token is already expired (current time would be greater, than token expiry time)
    if exp < 0 {
        return;
    }

    info!(
        "Blacklisting {} token with jti: {}",
        token_details.token, token_details.token_uuid
    );

    if let Err(_err) = save_to_redis(
        redis_client,
        &token_details.token_uuid.to_string(),
        &token_details.user_id.to_string(),
        exp as usize,
    )
    .await
    {
        error!("Error blacklisting token to Redis db");
    }
}

/// returns true if token is blacklisted
pub async fn token_is_blacklisted(redis_client: &Client, token_details: &TokenDetails) -> bool {
    if let Ok(user_id) = get_from_redis(redis_client, &token_details.token_uuid.to_string()).await {
        let msg = format!(
            "{}{}",
            "WARNING! someone just tried to use blacklisted token! User's id:"
                .bold()
                .bright_yellow(),
            user_id
        );
        warn!("{}", msg);
        true
    } else {
        false
    }
}
