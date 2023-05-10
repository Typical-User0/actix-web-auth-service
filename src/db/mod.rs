use crate::models::User;

use sqlx::postgres::PgQueryResult;
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

/// get user with provided email from database
/// if an error had occur, sqlx::Error is returned
/// if the user with provided email doesn't exist
/// Ok(None) is returned.
/// if there are no errors and user exists,
/// `User` struct is returned
pub async fn get_user_from_db_by_email(
    email: &str,
    db: &Pool<Postgres>,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
        .fetch_optional(db)
        .await
}

/// get user with provided UUID from database
/// if an error had occur, sqlx::Error is returned
/// if the user with provided UUID doesn't exist
/// Ok(None) is returned.
/// if there are no errors and user exists,
/// `User` struct is returned
pub async fn get_user_from_db_by_uuid(
    uuid: &Uuid,
    db: &Pool<Postgres>,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", uuid)
        .fetch_optional(db)
        .await
}

/// create new user with provided name, email and password_hash
/// if user was successfully created
/// returns `User` struct instance
/// otherwise returns sqlx::Error
pub async fn create_new_user(
    name: &str,
    email: &str,
    password_hash: &str,
    db: &Pool<Postgres>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
        name,
        email.to_lowercase(),
        password_hash,
    )
    .fetch_one(db)
    .await
}

/// set one time password for user
pub async fn set_otp_for_user(
    user_id: &Uuid,
    otp_base32: &str,
    otp_auth_url: &str,
    db: &Pool<Postgres>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET otp_base32 = $1,otp_auth_url=$2 WHERE id = $3",
        otp_base32,
        otp_auth_url,
        user_id
    )
    .execute(db)
    .await
}

/// remove one time password for user
pub async fn disable_otp_for_user(
    user_id: &Uuid,
    db: &Pool<Postgres>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET otp_base32 = NULL,otp_auth_url=NULL, otp_verified=FALSE, otp_enabled=FALSE WHERE id = $1", user_id)
        .execute(db)
        .await
}

/// enable and verify one time password for user
/// (mark otp_enabled and otp_verified as `TRUE`)
pub async fn enable_otp_for_user(
    user_id: &Uuid,
    db: &Pool<Postgres>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET otp_enabled=TRUE,otp_verified=TRUE WHERE id = $1",
        user_id
    )
    .execute(db)
    .await
}

/// check if user with provided email exists
/// if an error had occur, sqlx::Error is returned
/// if there are no error and user exists, `true` is returned
/// otherwise `false` is returned
pub async fn user_with_email_exists(email: &str, db: &Pool<Postgres>) -> Result<bool, sqlx::Error> {
    let result: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(email)
        .fetch_one(db)
        .await?
        .try_get(0)?;

    Ok(result)
}

/// check if user with provided uuid exists
/// if an error had occur, sqlx::Error is returned
/// if there are no error and user exists, `true` is returned
/// otherwise `false` is returned
pub async fn user_with_uuid_exists(uuid: &Uuid, db: &Pool<Postgres>) -> Result<bool, sqlx::Error> {
    let result: bool = sqlx::query!("SELECT EXISTS(SELECT 1 from users WHERE id = $1)", uuid)
        .fetch_one(db)
        .await?
        .exists
        .unwrap_or(false);

    Ok(result)
}
