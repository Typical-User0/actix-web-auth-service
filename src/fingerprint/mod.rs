// use crate::custom_errors::{CustomHttpError, Forbidden, InternalError};
use crate::hash::{sha512_hash_matches, sha512_hash_with_salt};
use actix_web::http::header::{ToStrError, USER_AGENT};
use actix_web::HttpRequest;
use colored::Colorize;
use derive_more::Display;
use log::{debug, error, warn};
use std::error::Error;

#[derive(Debug, Display)]
pub struct FingerPrintError(String);

impl Error for FingerPrintError {}

impl From<ToStrError> for FingerPrintError {
    fn from(value: ToStrError) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

impl From<argon2::password_hash::Error> for FingerPrintError {
    fn from(value: argon2::password_hash::Error) -> Self {
        Self {
            0: value.to_string(),
        }
    }
}

pub fn extract_fingerprint_from_request(req: &HttpRequest) -> Option<Vec<u8>> {
    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .map(|header_value| header_value.as_bytes().to_vec());

    user_agent
}

pub fn hash_fingerprint(fingerprint: &[u8]) -> String {
    let fingerprint = sha512_hash_with_salt(fingerprint);
    fingerprint
}

/// verifies http request signature
pub fn fingerprint_matches(req: &HttpRequest, token_fingerprint: &Option<String>) -> bool {
    // if token contains fingerprint we must check it against http request
    if let Some(token_fingerprint) = token_fingerprint {
        debug!("{}", token_fingerprint);

        let fingerprint = extract_fingerprint_from_request(&req);

        if let Some(fingerprint) = fingerprint {
            if !sha512_hash_matches(&fingerprint, &token_fingerprint) {
                warn!(
                    "Fingerprint doesn't match! User-agent: {}",
                    String::from_utf8_lossy(&fingerprint).bold().bright_red(),
                );
                return false;
            }
        } else {
            return false;
        }
    }
    true
}
