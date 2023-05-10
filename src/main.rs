use actix_cors::Cors;
use actix_limitation::{Limiter, RateLimiter};

use actix_web::dev::ServiceRequest;
use actix_web::middleware::Logger;
use actix_web::{http::header, web, App, HttpServer};

use colored::Colorize;
use dotenv::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::{debug, error, info};
use redis::Client;
use ring::signature::KeyPair;
use sqlx::postgres::PgPoolOptions;
use std::sync::Mutex;
use std::time::Duration;

use auth_service::config::Config;


use auth_service::{handlers, AppState};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    info!("Initializing server config...");

    let config = Config::init();

    info!(
        "{}",
        "✅ Server config is successfully initialized!"
            .bold()
            .green()
    );

    info!("Initializing rate limiter...");
    let limiter = web::Data::new(
        Limiter::builder("redis://127.0.0.1")
            .key_by(|req: &ServiceRequest| {
                // rate limit by IP
                // we will use cloudflare proxy,
                // so we call realip_remote_addr instead of peer_addr
                req.connection_info()
                    .realip_remote_addr()
                    .map(|str| str.to_string())
            })
            .limit(360)
            .period(Duration::from_secs(60))
            .build()
            .expect(&"failed to build limiter".red()),
    );

    info!(
        "{}",
        "✅ Successfully initialized rate limiter!".bold().green()
    );

    debug!("Server config: {:?}", config);

    info!("Connecting to database ...");

    let pool = match PgPoolOptions::new()
        .max_connections(100)
        .test_before_acquire(true)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            info!("{}", "✅ Connection to the database is successful!".green());
            pool
        }
        Err(err) => {
            error!(
                "🔥Failed to connect to the database: {}",
                err.to_string().bold().red()
            );
            std::process::exit(1);
        }
    };

    info!("Connecting to the redis...");
    let redis_client = match Client::open(config.redis_url.to_owned()) {
        Ok(client) => {
            info!("{}", "✅ Connection to the redis is successful!".green());
            client
        }
        Err(err) => {
            error!(
                "🔥 Error connecting to Redis: {}",
                err.to_string().bold().red()
            );
            std::process::exit(1);
        }
    };

    info!("{}", "🚀 Server started successfully".bold().green());

    info!("Generating Ed25519 key pairs for access and refresh tokens...");
    let (refresh_encoding_key, refresh_decoding_key) = generate_key_pair();
    let (access_encoding_key, access_decoding_key) = generate_key_pair();

    info!(
        "{}",
        "✅ Ed25519 key pairs are successfully generated!"
            .bold()
            .green()
    );

    let app_state = web::Data::new(AppState {
        db: pool.clone(),
        env: config.clone(),
        redis_client: redis_client.clone(),
        refresh_encoding_key: Mutex::new(refresh_encoding_key),
        refresh_decoding_key: Mutex::new(refresh_decoding_key),
        access_encoding_key: Mutex::new(access_encoding_key),
        access_decoding_key: Mutex::new(access_decoding_key),
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&config.client_origin)
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
            ])
            .supports_credentials();
        App::new()
            .wrap(RateLimiter::default())
            .wrap(cors)
            .wrap(Logger::default())
            .app_data(limiter.clone())
            .app_data(app_state.clone())
            .configure(handlers::config)
    })
    .bind(("localhost", 8000))?
    .run()
    .await
}

fn generate_key_pair() -> (EncodingKey, DecodingKey) {
    let rng = ring::rand::SystemRandom::new();

    info!("Generating Ed25519 pkcs8 bytes...");
    let pkcs8_bytes = match ring::signature::Ed25519KeyPair::generate_pkcs8(&rng) {
        Ok(val) => val,
        Err(err) => {
            // Todo: error handling (exiting is probably bad move)
            error!(
                "Error generating pkcs8 bytes: {}",
                err.to_string().bold().red()
            );
            std::process::exit(1);
        }
    };

    info!(
        "{}",
        "✅ successfully generated pkcs8 bytes!".bold().green()
    );

    info!("Generating Ed25519 key pair from pkcs8 bytes...");

    let key_pair = match ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
        Ok(key_pair) => key_pair,
        Err(err) => {
            error!("Error generating Ed25519 key pair from pkcs8: {}", err);
            // Todo: error handling (exiting is probably bad move)
            std::process::exit(1);
        }
    };

    debug!("key pair: {:?}", key_pair);

    info!(
        "{}",
        "✅ Successfully generated Ed25519 key pair from pkcs8 bytes!"
            .bold()
            .green()
    );

    let encoding_key = EncodingKey::from_ed_der(pkcs8_bytes.as_ref());
    let decoding_key = DecodingKey::from_ed_der(key_pair.public_key().as_ref());

    (encoding_key, decoding_key)
}
