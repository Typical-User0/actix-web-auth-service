use actix_web::body::MessageBody;
use actix_web::error::ErrorForbidden;
use chrono::prelude::*;
use jsonwebtoken::{DecodingKey, EncodingKey};
use lazy_static::lazy_static;
use std::error::Error;

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use validator::{Validate, ValidationError};

use regex::Regex;
use uuid::Uuid;

use crate::config::Config;
use crate::db::{
    create_new_user, disable_otp_for_user, enable_otp_for_user, get_user_from_db_by_email,
    get_user_from_db_by_uuid, set_otp_for_user, user_with_email_exists, user_with_uuid_exists,
};
use crate::hash::argon2id_hash;
use crate::totp::{generate_totp, totp_is_valid, OtpData, OtpError};
use crate::validation::argon2id_hash_matches;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: String,
    pub verified: bool,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn verified(&self) -> bool {
        self.verified
    }

    pub fn otp_base32(&self) -> &Option<String> {
        &self.otp_base32
    }

    pub fn created_at(&self) -> &Option<DateTime<Utc>> {
        &self.created_at
    }

    pub fn updated_at(&self) -> &Option<DateTime<Utc>> {
        &self.updated_at
    }

    /// returns true if provided password is indeed user's password
    pub fn password_is_correct(&self, password: &str) -> bool {
        let is_correct = argon2id_hash_matches(&self.password, &password);

        is_correct
    }

    /// adds user to database with provided name, email and password
    /// (password will be hashed inside this method)
    /// returns created user on success and CustomHttpError on failure
    pub async fn add_to_database(
        db: &Pool<Postgres>,
        name: &str,
        email: &str,
        password: &str,
    ) -> Result<Self, Box<dyn Error>> {
        // hash user's password with argon2id
        let password_hash = argon2id_hash(password.as_bytes()).map_err(|x| format!("{}", x))?;
        let user = create_new_user(name, email, &password_hash, db).await?;

        Ok(user)
    }

    /// retrieves user with provided `id` from database
    /// and constructs `User` struct based on query result
    /// returns CustomHttpError if an error occurred
    pub async fn get_from_db_by_id(
        db: &Pool<Postgres>,
        id: &Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        let query_result = get_user_from_db_by_uuid(id, db).await?;

        Ok(query_result)
    }

    /// retrieves user with provided `email` from database
    /// and constructs `User` struct based on query result
    /// returns error if an error occurred
    pub async fn get_from_db_by_email(
        db: &Pool<Postgres>,
        email: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let query_result = get_user_from_db_by_email(&email, db).await?;

        Ok(query_result)
    }

    /// check if provided credentials are correct (email and password)
    pub async fn credentials_are_valid(&self, email: &str, password: &str) -> bool {
        self.password_is_correct(password) && self.email == email
    }

    /// returns true if user with provided email exists in database
    /// otherwise returns false
    /// returns error if an error occurred
    pub async fn with_email_exists(db: &Pool<Postgres>, email: &str) -> Result<bool, sqlx::Error> {
        let exists = user_with_email_exists(email, db).await?;

        Ok(exists)
    }

    /// returns true if user with provided `id` exists in database
    /// otherwise returns false
    /// returns CustomHttpError if an error occurred
    pub async fn with_id_exists(db: &Pool<Postgres>, id: &Uuid) -> Result<bool, sqlx::Error> {
        let exists = user_with_uuid_exists(id, db).await?;

        Ok(exists)
    }

    pub fn otp_enabled(&self) -> bool {
        self.otp_enabled
    }

    pub fn otp_verified(&self) -> bool {
        self.otp_verified
    }

    pub async fn generate_otp(&mut self, db: &Pool<Postgres>) -> Result<OtpData, Box<dyn Error>> {
        // generate otp
        let otp_data = generate_totp(&self.email)?;

        self.otp_base32 = Some(otp_data.otp_base32.clone());
        self.otp_auth_url = Some(otp_data.otp_auth_url.clone());

        // let otp_auth_url = format!("otpauth://totp/<issuer>:<account_name>?secret=<secret>&issuer=<issuer>");

        // update database record, if an error occurred, return CustomHttpError
        set_otp_for_user(&self.id, &otp_data.otp_base32, &otp_data.otp_auth_url, db).await?;

        Ok(otp_data)
    }

    pub async fn enable_otp(&mut self, db: &Pool<Postgres>) -> Result<(), sqlx::Error> {
        self.otp_verified = true;
        self.otp_enabled = true;
        enable_otp_for_user(self.id(), db).await?;

        Ok(())
    }

    pub fn otp_is_valid(&self, token: &str) -> Result<bool, OtpError> {
        if let Some(otp_base32) = &self.otp_base32() {
            let is_valid = totp_is_valid(&otp_base32, token)?;

            Ok(is_valid)
        } else {
            Ok(false)
        }
    }

    pub async fn disable_otp(&mut self, db: &Pool<Postgres>) -> Result<(), sqlx::Error> {
        disable_otp_for_user(&self.id, db).await?;

        self.otp_verified = false;
        self.otp_enabled = false;
        Ok(())
    }
}

/// validate password
/// it must be between 8 and 100 chars long,
/// contain at least 1 uppecase letter,
/// at least 1 lowercase letter,
/// at least 1 digit.
/// it must NOT contain whitespace
fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 || password.len() > 100 {
        return Err(ValidationError::new("Password validation failed"));
    }

    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_digit(10);
    }
    if !has_whitespace && has_upper && has_lower && has_digit && password.len() >= 8 {
        Ok(())
    } else {
        return Err(ValidationError::new("Password validation failed"));
    }
}

/// Schema for registering a new user
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterUserSchema {
    #[validate(length(
        min = 3,
        max = 100,
        message = "Name must be greater than 3 chars and less than or equal to 100 chars"
    ))]
    pub name: String,
    #[validate(email)]
    pub email: String,
    #[validate(custom(
        function = "validate_password",
        message = "Password must contain at least one upper case, lower case and number and be between 8 and 100 characters long. Don't use spaces"
    ))]
    pub password: String,
}

/// Schema for login to a user's account
#[derive(Debug, Deserialize)]
pub struct LoginUserSchema {
    pub email: String,
    pub password: String,
}

/// Schema for generating one-time password for user
#[derive(Debug, Deserialize)]
pub struct GenerateOTPSchema {
    pub email: String,
    pub user_id: String,
    pub password: String,
}

/// Schema for verifying one-time password for user
#[derive(Debug, Deserialize)]
pub struct VerifyOTPSchema {
    pub user_id: String,
    pub token: String,
}

/// Schema for disabling one-time password for user
#[derive(Debug, Deserialize)]
pub struct DisableOTPSchema {
    pub user_id: String,
    pub password: String,
}

/// State of the web application
pub struct AppState {
    pub db: Pool<Postgres>,
    pub env: Config,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}
