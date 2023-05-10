use ::redis::Client;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::{Pool, Postgres};
use std::sync::Mutex;

use crate::config::Config;

#[macro_use]
extern crate lazy_static;

pub mod config;
mod cookies;
mod custom_errors;
pub mod db;
mod fingerprint;
pub mod handlers;
pub mod hash;
pub mod jwt_auth;
pub mod models;
mod redis;
mod response;
pub mod token;
mod totp;
mod validation;

pub struct AppState {
    pub env: Config,
    pub db: Pool<Postgres>,
    pub redis_client: Client,

    // use mutex, because these keys will be rotated from time to time
    // for security concerns
    pub access_encoding_key: Mutex<EncodingKey>,
    pub access_decoding_key: Mutex<DecodingKey>,
    pub refresh_encoding_key: Mutex<EncodingKey>,
    pub refresh_decoding_key: Mutex<DecodingKey>,
}
