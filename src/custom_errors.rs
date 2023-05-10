use actix_web::{
    error,
    http::{header::ContentType, StatusCode},
    HttpResponse,
};
use derive_more::{Display, Error};
use log::error;
use std::fmt;

use serde::Serialize;
use serde_json::json;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

impl ErrorResponse {
    pub fn new(message: &str) -> Self {
        ErrorResponse {
            status: String::from("fail"),
            message: String::from(message),
        }
    }
}

pub trait IntoHttpError<T> {
    fn http_error(
        self,
        message: &str,
        status_code: StatusCode,
    ) -> core::result::Result<T, actix_web::Error>;

    fn http_internal_error(self) -> core::result::Result<T, actix_web::Error>
    where
        Self: std::marker::Sized,
    {
        self.http_error("Internal Error", StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn http_bad_req_error(self, message: &str) -> Result<T, actix_web::Error>
    where
        Self: Sized,
    {
        self.http_error(message, StatusCode::BAD_REQUEST)
    }

    fn http_unauthorized_error(self, message: &str) -> Result<T, actix_web::Error>
    where
        Self: Sized,
    {
        self.http_error(message, StatusCode::UNAUTHORIZED)
    }

    fn http_forbidden_error(self, message: &str) -> Result<T, actix_web::Error>
    where
        Self: Sized,
    {
        self.http_error(message, StatusCode::FORBIDDEN)
    }

    fn http_not_found_error(self, message: &str) -> Result<T, actix_web::Error>
    where
        Self: Sized,
    {
        self.http_error(message, StatusCode::NOT_FOUND)
    }
}

impl<T, E: std::fmt::Debug> IntoHttpError<T> for core::result::Result<T, E> {
    fn http_error(
        self,
        message: &str,
        status_code: StatusCode,
    ) -> core::result::Result<T, actix_web::Error> {
        match self {
            Ok(val) => Ok(val),
            Err(err) => {
                error!("http_error: {:?}", err);
                Err(error::InternalError::new(ErrorResponse::new(message), status_code).into())
            }
        }
    }
}
