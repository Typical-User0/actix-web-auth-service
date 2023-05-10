use std::str::FromStr;

use actix_web::error::{ErrorConflict, ErrorForbidden, ErrorUnauthorized};
use actix_web::web::ReqData;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use actix_web_httpauth::middleware::HttpAuthentication;

use chrono::Utc;
use colored::Colorize;
use log::{debug, error, warn};

use serde_json::json;

use uuid::Uuid;
use validator::Validate;

use crate::cookies::{build_auth_cookies, clear_auth_cookies};
use crate::db::{
    create_new_user, disable_otp_for_user, enable_otp_for_user, get_user_from_db_by_email,
    get_user_from_db_by_uuid, set_otp_for_user, user_with_email_exists,
};
use crate::fingerprint::{extract_fingerprint_from_request, hash_fingerprint};
use crate::hash::argon2id_hash;
use crate::models::{DisableOTPSchema, GenerateOTPSchema, VerifyOTPSchema};
use crate::redis::{get_from_redis, save_to_redis};

use crate::custom_errors::{ErrorResponse, IntoHttpError};
use crate::jwt_auth::jwt_validator;
use crate::token::{blacklist_token, token_is_blacklisted, TokenDetails};
use crate::totp::{generate_totp, totp_is_valid};
use crate::validation::argon2id_hash_matches;
use crate::{
    models::{LoginUserSchema, RegisterUserSchema, User},
    response::FilteredUser,
    token, AppState,
};

/// To ensure that sensitive information such as
/// hashed passwords is not exposed,
/// this function utilizes the `FilteredUser` struct to
/// filter the Postgres database records.
/// It basically converts `User` struct to `FilteredUser` struct
fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id().to_string(),
        email: user.email().to_owned(),
        name: user.name().to_owned(),
        role: user.role().to_owned(),
        verified: user.verified(),
        createdAt: user.created_at().unwrap_or(Utc::now()),
        updatedAt: user.updated_at().unwrap_or(Utc::now()),
        otp_enabled: user.otp_enabled(),
        otp_verified: user.otp_verified(),
    }
}

#[post("/auth/register")]
async fn register_user_handler(
    body: web::Json<RegisterUserSchema>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    // validate user input
    body.validate().http_bad_req_error("Bad request")?;

    // check if user with provided email already exists
    let exists = User::with_email_exists(&data.db, &body.email)
        .await
        .http_internal_error()?;

    // if user with provided email exists, return a 409 conflict error
    if exists {
        return Err(ErrorConflict(ErrorResponse::new(
            "The user with this email already exists",
        )));
    }

    // add user to database
    let user = User::add_to_database(&data.db, &body.name, &body.email, &body.password)
        .await
        .http_internal_error()?;

    let user_response = filter_user_record(&user);

    let user_response = json!({"status": "success", "data": json!({
        "user": user_response
    })});

    Ok(HttpResponse::Ok().json(user_response))
}

/// If the passwords match, the token::generate_jwt_token()
/// helper function will be called to sign both the access
/// and refresh tokens with their corresponding private keys.
/// The metadata of each token will be securely stored in the
/// Redis database using the redis_client.set_ex() method.
///
/// Finally, the tokens will be included in the response
/// as HTTP-only cookies, and a copy of the access token
/// will be sent in the JSON object. This will enable the
/// user to include the access token as a Bearer token in
/// the Authorization header of future requests that
/// require authentication.
#[post("/auth/login")]
async fn login_user_handler(
    req: HttpRequest,
    body: web::Json<LoginUserSchema>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    // fetch user with provided email
    let user = User::get_from_db_by_email(&data.db, &body.email)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    // if provided password is not valid return a 400 Bad request response
    if !user.password_is_correct(&body.password) {
        return Err(ErrorUnauthorized(ErrorResponse::new(
            "Invalid email or password",
        )));
    }

    let fingerprint = extract_fingerprint_from_request(&req);

    let mut fingerprint_option = None;

    if let Some(fingerprint) = fingerprint {
        let fingerprint_hash = hash_fingerprint(&fingerprint);
        fingerprint_option = Some(fingerprint_hash);
    }

    // acquire mutex on access and refresh tokens encoding keys
    let access_encoding_key = data.access_encoding_key.lock().http_internal_error()?;
    let refresh_encoding_key = data.refresh_encoding_key.lock().http_internal_error()?;

    // generate new access & refresh token pair
    let access_token_details = token::generate_jwt_token(
        user.id(),
        data.env.access_token_max_age,
        &access_encoding_key,
        fingerprint_option.clone(),
    )
    .http_internal_error()?;

    let refresh_token_details = token::generate_jwt_token(
        user.id(),
        data.env.refresh_token_max_age,
        &refresh_encoding_key,
        fingerprint_option.clone(),
    )
    .http_internal_error()?;

    let cookies = build_auth_cookies(
        &refresh_token_details.token,
        "true",
        data.env.refresh_token_max_age * 60,
    );

    // filter out user sensitive information
    let user_response = filter_user_record(&user);

    Ok(HttpResponse::Ok()
        .cookie(cookies.refresh_token_cookie)
        .cookie(cookies.logged_in_cookie)
        .json(json!({"status": "success", "access_token": access_token_details.token, "user": user_response})))
}

#[get("/auth/refresh")]
async fn refresh_tokens_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    let _message = "could not refresh access token";

    let refresh_token = req
        .cookie("refresh_token")
        .ok_or("refresh token cookie is not present")
        .http_forbidden_error("Forbidden")?
        .value()
        .to_string();

    debug!("refresh token: {}", refresh_token);

    let refresh_decoding_key = data.refresh_decoding_key.lock().http_internal_error()?;

    // get old refresh token (which user sent in the request's cookie)
    let old_refresh_token_details = token::verify_jwt_token(&refresh_decoding_key, &refresh_token)
        .http_forbidden_error("Forbidden")?;

    // if refresh token is in redis db blacklist, it means it was already used
    // so probably someone is trying to hack user
    if token_is_blacklisted(&data.redis_client, &old_refresh_token_details).await {
        return Err(ErrorForbidden(ErrorResponse::new("Forbidden")));
    }

    // if refresh token is not in redis db, it means it wasn't used until now,
    // we need to add it to the database,
    // in order to detect potential interception
    // of refresh token in the future
    blacklist_token(&data.redis_client, &old_refresh_token_details).await;

    let user = User::get_from_db_by_id(&data.db, &old_refresh_token_details.user_id)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    // get raw fingerprint from request headers
    let mut fingerprint_option = extract_fingerprint_from_request(&req);

    let mut fingerprint_str_option = None;

    // if it is presented, hash it
    if let Some(fingerprint) = fingerprint_option {
        let fingerprint_hash = hash_fingerprint(&fingerprint);
        fingerprint_str_option = Some(fingerprint_hash);
    }

    // issue new access token
    let access_token_details = token::generate_jwt_token(
        user.id(),
        data.env.access_token_max_age,
        &data.access_encoding_key.lock().unwrap(),
        fingerprint_str_option.clone(),
    )
    .http_internal_error()?;

    let refresh_encoding_key = data.refresh_encoding_key.lock().http_internal_error()?;

    // issue new refresh token
    let refresh_token_details = token::generate_jwt_token(
        user.id(),
        data.env.refresh_token_max_age,
        &refresh_encoding_key,
        fingerprint_str_option,
    )
    .http_internal_error()?;

    let auth_cookies = build_auth_cookies(
        &refresh_token_details.token,
        "true",
        refresh_token_details.expires_in,
    );

    Ok(HttpResponse::Ok()
        .cookie(auth_cookies.refresh_token_cookie)
        .cookie(auth_cookies.logged_in_cookie)
        .json(json!({"status": "success", "access_token": access_token_details.token})))
}

#[get("/auth/logout")]
async fn logout_handler(_req: HttpRequest, _data: web::Data<AppState>) -> impl Responder {
    // clear cookies
    let auth_cookies = clear_auth_cookies();

    HttpResponse::Ok()
        .cookie(auth_cookies.refresh_token_cookie)
        .cookie(auth_cookies.logged_in_cookie)
        .json(json!({"status": "success"}))
}

#[get("/users/me")]
async fn get_me_handler(
    req: Option<ReqData<TokenDetails>>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    let req_data = req
        .ok_or("token details are not presented in request data")
        .http_unauthorized_error("Unauthorized")?;
    // get user from database by id
    let user = User::get_from_db_by_id(&data.db, &req_data.user_id)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    let user_response = filter_user_record(&user);

    let json_response = json!({
        "status":  "success",
        "data": json!({
            "user": user_response
        })
    });

    Ok(HttpResponse::Ok().json(json_response))
}

// TODO: recovery 2FA codes (10 codes, each can be used once)
#[post("/auth/otp/generate")]
async fn generate_otp_handler(
    body: web::Json<GenerateOTPSchema>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    let uuid = Uuid::parse_str(&body.user_id).http_bad_req_error("Invalid id")?;

    // fetch user with provided id
    let mut user = User::get_from_db_by_id(&data.db, &uuid)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    // check if provided credentials are valid
    if user
        .credentials_are_valid(&body.email, &body.password)
        .await
    {
        let otp_data = user.generate_otp(&data.db).await?;

        Ok(HttpResponse::Ok()
            .json(json!({"base32":otp_data.otp_base32, "otpauth_url": otp_data.otp_auth_url} )))
    } else {
        // if credentials are wrong, return 403 Forbidden
        Err(ErrorForbidden(ErrorResponse::new("Forbidden")))
    }
}

#[post("/auth/otp/verify")]
async fn verify_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    let uuid = Uuid::from_str(&body.user_id).http_bad_req_error("Invalid id")?;

    // get user from database by id
    let mut user = User::get_from_db_by_id(&data.db, &uuid)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    // return an error if code is invalid, otherwise proceed
    let otp_is_valid = user.otp_is_valid(&body.token).http_internal_error()?;

    // mark user's one-time password as verified in database
    user.enable_otp(&data.db).await.http_internal_error()?;

    let user_response = filter_user_record(&user);

    // return updated user data
    Ok(HttpResponse::Ok().json(json!({"otp_verified": true, "user": user_response})))
}

#[post("/auth/otp/validate")]
async fn validate_otp_handler(
    body: web::Json<VerifyOTPSchema>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    let uuid = Uuid::from_str(&body.user_id).http_bad_req_error("Invalid id")?;

    let user = User::get_from_db_by_id(&data.db, &uuid)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    // check if one-time password feature is enabled
    if !user.otp_enabled() {
        return Err(ErrorForbidden(ErrorResponse::new("2FA is not enabled")));
    }

    if !user.otp_is_valid(&body.token).http_internal_error()? {
        return Err(ErrorForbidden(ErrorResponse::new("Invalid 2FA code")));
    }

    Ok(HttpResponse::Ok().json(json!({"otp_valid": true})))
}

#[post("/auth/otp/disable")]
async fn disable_otp_handler(
    body: web::Json<DisableOTPSchema>,
    data: web::Data<AppState>,
) -> Result<impl Responder, actix_web::Error> {
    let uuid = Uuid::from_str(&body.user_id).http_bad_req_error("Invalid id")?;

    let mut user = User::get_from_db_by_id(&data.db, &uuid)
        .await
        .http_internal_error()?
        .ok_or("User not found")
        .http_not_found_error("User not found")?;

    // if provided password is correct, disable otp
    if user.password_is_correct(&body.password) {
        user.disable_otp(&data.db).await.http_internal_error()?;
    }

    // filter out user sensitive information
    let user_response = filter_user_record(&user);

    Ok(HttpResponse::Ok().json(json!({"user": user_response, "otp_disabled": true})))
}

#[get("/healthchecker")]
async fn health_checker_handler() -> impl Responder {
    const MESSAGE: &str = "Actix-web, Postgres, jwt Ed25519 access and refresh tokens, 2FA";

    HttpResponse::Ok().json(json!({"status": "success", "message": MESSAGE}))
}

pub fn config(conf: &mut web::ServiceConfig) {
    // middleware for jwt authentication
    let bearer_middleware = HttpAuthentication::bearer(jwt_validator);

    let scope = web::scope("/api")
        .service(health_checker_handler)
        .service(register_user_handler)
        .service(login_user_handler)
        .service(refresh_tokens_handler)
        .service(generate_otp_handler)
        .service(verify_otp_handler)
        .service(validate_otp_handler)
        .service(disable_otp_handler)
        .service(
            web::scope("")
                .wrap(bearer_middleware)
                .service(get_me_handler)
                .service(logout_handler),
        );

    conf.service(scope);
}
