use redis::{AsyncCommands, RedisResult};

/// save key value pair with specific expiry time in seconds
/// in Redis DB
pub async fn save_to_redis(
    redis_client: &redis::Client,
    key: &str,
    value: &str,
    exp: usize,
) -> RedisResult<()> {
    redis_client
        .get_async_connection()
        .await?
        .set_ex(key, value, exp)
        .await
}

/// returns value of provided key if it's presented in Redis DB
pub async fn get_from_redis(redis_client: &redis::Client, key: &str) -> RedisResult<String> {
    redis_client.get_async_connection().await?.get(key).await
}
