#![allow(unexpected_cfgs)]

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use dotenvy::dotenv;
use futures::StreamExt;
use matrix_sdk::{
    AuthSession, Client, SessionMeta, SessionTokens,
    authentication::matrix::MatrixSession,
    ruma::{DeviceId, RoomId, UserId, events::macros::EventContent},
};
use serde::{Deserialize, Serialize};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod delegation;
mod destinations;
mod ranges;

const DB_URL: &str = "sqlite://./db.sqlite?mode=rwc";
const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_CONCURRENT_RESOLUTIONS: usize = 1;

#[derive(Debug, Clone, Serialize, Deserialize, EventContent)]
#[ruma_event(type = "m.policy.rule.server", kind = State, state_key_type = String)]
pub struct ServerPolicyEventContent {
    pub entity: String,
    pub reason: String,
    pub recommendation: String,
}

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
            CREATE TABLE IF NOT EXISTS seen_servers (
                server_name TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS blocked_servers (
                server_name TEXT PRIMARY KEY
            );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let client = Client::builder()
        .homeserver_url(std::env::var("HOMESERVER").unwrap())
        .build()
        .await
        .unwrap();

    client
        .restore_session(AuthSession::Matrix(MatrixSession {
            meta: SessionMeta {
                user_id: <&UserId>::try_from(std::env::var("USER_ID").unwrap().as_str())
                    .unwrap()
                    .to_owned(),
                device_id: <&DeviceId>::from(std::env::var("DEVICE_ID").unwrap().as_str())
                    .to_owned(),
            },
            tokens: SessionTokens {
                access_token: std::env::var("TOKEN").unwrap(),
                refresh_token: None,
            },
        }))
        .await
        .unwrap();

    info!(
        "Logged in as {}. Starting initial sync...",
        client.user_id().unwrap()
    );

    client.sync_once(Default::default()).await.unwrap();

    // Every CHECK_INTERVAL seconds, check for any new destinations and block them if they're
    // in the Cloudflare network.
    let seen: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(
        sqlx::query!("SELECT server_name FROM seen_servers;")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.server_name.unwrap())
            .collect::<std::collections::HashSet<_>>(),
    ));

    loop {
        let destinations = destinations::get_destinations().await;

        let new_destinations = destinations
            .iter()
            .filter(|d| !seen.clone().lock().unwrap().contains(*d))
            .cloned()
            .collect::<Vec<_>>();

        futures::stream::iter(new_destinations.iter())
            .for_each_concurrent(Some(MAX_CONCURRENT_RESOLUTIONS), |dest| {
                let seen = seen.clone();
                let pool = pool.clone();
                let client = client.clone();
                async move {
                    info!("Found new server: {dest}");

                    if let Ok(ips) = delegation::resolve_server_name(dest).await {
                        let cloudflare_ranges =
                            ranges::get_cloudflare_ranges().await.unwrap_or_default();
                        if ips
                            .iter()
                            .any(|ip| cloudflare_ranges.iter().any(|range| range.contains(ip)))
                        {
                            info!("{dest} is behind Cloudflare, blocking it!");

                            let room = client
                                .get_room(
                                    <&RoomId as TryFrom<&str>>::try_from(
                                        std::env::var("POLICY_ROOM_ID").unwrap().as_str(),
                                    )
                                    .unwrap(),
                                )
                                .unwrap();

                            let bye_bye_event = ServerPolicyEventContent {
                                entity: dest.clone(),
                                reason: "Server is behind Cloudflare".to_string(),
                                recommendation: "m.ban".to_string(),
                            };
                            room.send_state_event_for_key(&dest.clone(), bye_bye_event)
                                .await
                                .unwrap();

                            sqlx::query!(
                                "INSERT OR IGNORE INTO blocked_servers (server_name) VALUES (?1);",
                                dest
                            )
                            .execute(&pool)
                            .await
                            .unwrap();
                        } else {
                            info!(
                                "Not blocking {dest} because it does not resolve to a Cloudflare IP"
                            );
                        }
                    }

                    // Add the server to the seen set and database
                    seen.lock().unwrap().insert(dest.clone());
                    sqlx::query!("INSERT INTO seen_servers (server_name) VALUES (?1);", dest)
                        .execute(&pool)
                        .await
                        .unwrap();
                }
            })
            .await;

        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}
