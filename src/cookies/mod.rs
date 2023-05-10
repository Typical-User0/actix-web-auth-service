use actix_web::cookie::time::Duration as ActixWebDuration;
use actix_web::cookie::Cookie;
pub struct AuthCookies<'a> {
    pub refresh_token_cookie: Cookie<'a>,
    pub logged_in_cookie: Cookie<'a>,
}

pub fn build_auth_cookies<'a>(
    refresh_token: &'a str,
    logged_in: &'a str,
    refresh_token_maxage: i64,
) -> AuthCookies<'a> {
    let refresh_token_cookie = Cookie::build("refresh_token", refresh_token)
        .path("/")
        .max_age(ActixWebDuration::new(refresh_token_maxage, 0))
        .same_site(actix_web::cookie::SameSite::None)
        .secure(true)
        .http_only(true)
        .finish();

    let logged_in_cookie = Cookie::build("logged_in", logged_in)
        .path("/")
        .max_age(ActixWebDuration::new(refresh_token_maxage, 0))
        .http_only(false)
        .finish();

    return AuthCookies {
        refresh_token_cookie,
        logged_in_cookie,
    };
}

pub fn clear_auth_cookies<'a>() -> AuthCookies<'a> {
    let refresh_token_cookie = Cookie::build("refresh_token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();
    let logged_in_cookie = Cookie::build("logged_in", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();

    return AuthCookies {
        refresh_token_cookie,
        logged_in_cookie,
    };
}
