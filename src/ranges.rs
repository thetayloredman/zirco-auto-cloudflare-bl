use std::{sync::RwLock, time::Instant};

use ipnet::IpNet;
use once_cell::sync::Lazy;

const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_hours(24);
static CLOUDFLARE_RANGES: Lazy<RwLock<(Instant, Vec<IpNet>)>> = Lazy::new(||
    // Initially empty, so put the timestamp far in the past to force an immediate refresh
    RwLock::new((Instant::now() - REFRESH_INTERVAL * 2, Vec::new())));

/// Returns the current list of Cloudflare IP ranges, refreshing it if it's older than 24 hours.
pub async fn get_cloudflare_ranges() -> anyhow::Result<Vec<IpNet>> {
    {
        // Check if we can simply return the cached ranges
        let guard = CLOUDFLARE_RANGES.read().unwrap();
        if guard.0.elapsed() < REFRESH_INTERVAL {
            return Ok(guard.1.clone());
        }
    }

    // Need to refresh the ranges
    let mut guard = CLOUDFLARE_RANGES.write().unwrap();
    // Check again in case another thread already refreshed while we were waiting for the lock
    if guard.0.elapsed() < REFRESH_INTERVAL {
        return Ok(guard.1.clone());
    }

    let resp = reqwest::get("https://api.cloudflare.com/client/v4/ips").await?;
    let json: serde_json::Value = resp.json().await?;
    let mut ranges = Vec::new();

    if let Some(ipv4_ranges) = json
        .get("result")
        .and_then(|r| r.get("ipv4_cidrs"))
        .and_then(|r| r.as_array())
    {
        for range in ipv4_ranges {
            if let Some(range_str) = range.as_str()
                && let Ok(ipnet) = range_str.parse()
            {
                ranges.push(ipnet);
            }
        }
    }

    if let Some(ipv6_ranges) = json
        .get("result")
        .and_then(|r| r.get("ipv6_cidrs"))
        .and_then(|r| r.as_array())
    {
        for range in ipv6_ranges {
            if let Some(range_str) = range.as_str()
                && let Ok(ipnet) = range_str.parse()
            {
                ranges.push(ipnet);
            }
        }
    }

    *guard = (Instant::now(), ranges.clone());

    Ok(ranges)
}
