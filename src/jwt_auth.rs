use core::fmt;
use std::ops::Deref;

use actix_web::dev::ServiceRequest;
use actix_web::error::{ErrorInternalServerError, ErrorNotFound, ErrorUnauthorized};

use actix_web::{web, FromRequest};
use actix_web::{Error, HttpMessage};

use log::{debug, error, info};

use serde::Serialize;

use crate::db::user_with_uuid_exists;
use crate::fingerprint::fingerprint_matches;

use crate::token;

use crate::token::blacklist_token;
use crate::AppState;
use colored::Colorize;

// use crate::custom_errors::{CustomHttpError, ErrorResponse, IntoHttpError, NotFound, Unauthorized};
use crate::custom_errors::ErrorResponse;
use crate::models::User;
/// When a user attempts to access a protected route,
/// the JWT middleware will first search for the token in the Authorization header.
/// If it is not found there, it will check the Cookies object for the access_token key.
/// If the token cannot be found in either location, the middleware will
/// send a 401 Unauthorized response with the message
/// “You are not logged in, please provide token” to the client.
///
/// However, if the token is present, the middleware will call the token::verify_jwt_token()
/// function to verify its authenticity. If the token is valid,
/// the function will return the token’s metadata, which will be used in the next step to query
/// the Redis database to check whether the user associated with the token has a valid session.
/// (If the token metadata is found in the Redis database, it indicates that the user’s session is still active.)
///
/// If the user has an active session, the middleware will use the user’s ID returned from the Redis query to check
/// if the user associated with the token exists in the PostgreSQL database.
/// If the user is found, the middleware will return the corresponding record obtained from the query.
///
use actix_web_httpauth::extractors::bearer::BearerAuth;

pub async fn jwt_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let access_token = credentials.token();

    debug!("bearer token: {}", access_token.bold().green());

    let request = req.request().clone();

    let data = request.app_data::<web::Data<AppState>>();
    if let Some(data) = data {
        let access_decoding_key_result = data.access_decoding_key.lock();

        if let Ok(access_decoding_key) = access_decoding_key_result {
            let access_token_details =
                // todo: proper error handling
                match token::verify_jwt_token(&access_decoding_key, &access_token) {
                    Ok(token_details) => token_details,
                    Err(err) => {
                        error!("Error verifying json: {}", err);
                        return Err((ErrorUnauthorized("Unauthorized"), ServiceRequest::from_request(request.clone())));
                    }
                };

            // blacklist token if fingerprint doesn't match
            // (potential hacking activity)
            if !fingerprint_matches(req.request(), &access_token_details.fingerprint) {
                blacklist_token(&data.redis_client, &access_token_details).await;

                return Err((
                    ErrorUnauthorized("Unauthorized"),
                    ServiceRequest::from_request(request.clone()),
                ));
            }

            // check if user exists
            let user_exists_result =
                User::with_id_exists(&data.db, &access_token_details.user_id).await;

            match user_exists_result {
                Ok(exists) => {
                    let json_error = ErrorResponse::new("User not found");

                    if !exists {
                        return Err((
                            ErrorNotFound(json_error),
                            ServiceRequest::from_request(request.clone()),
                        ));
                    }
                }
                Err(err) => {
                    error!(
                        "Error searching for user with provided UUID: {}",
                        err.to_string().bold().red()
                    );

                    return Err((
                        ErrorInternalServerError("Internal server error"),
                        ServiceRequest::from_request(request.clone()),
                    ));
                }
            }

            // insert access token info into the request so handlers can access it
            req.extensions_mut().insert(access_token_details);
            Ok(req)
        } else {
            return Err((
                ErrorInternalServerError((ErrorResponse::new("Internal Server Error"))),
                ServiceRequest::from_request(request.clone()),
            ));
        }
    } else {
        return Err((
            ErrorInternalServerError((ErrorResponse::new("Internal Server Error"))),
            ServiceRequest::from_request(request.clone()),
        ));
    }
}
