use dotenvy::dotenv;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod delegation;
mod ranges;

const DB_URL: &str = "sqlite://./db.sqlite?mode=rwc";

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let pool = sqlx::SqlitePool::connect(DB_URL).await.unwrap();

    sqlx::query(
        r#"
            CREATE TABLE IF NOT EXISTS blocked_servers (
                server_name TEXT PRIMARY KEY
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    dbg!(ranges::get_cloudflare_ranges().await);
    dbg!(delegation::resolve_server_name("chat.blahaj.zone").await);
}
