use hickory_resolver::{IntoName, Resolver, TokioResolver};
use once_cell::sync::Lazy;
use std::net::IpAddr;
use tracing::debug;

/// Resolve a `server_name` to its federation IP.
pub async fn resolve_server_name(server_name: &str) -> anyhow::Result<Vec<IpAddr>> {
    static RESOLVER: Lazy<TokioResolver> = Lazy::new(|| Resolver::builder_tokio().unwrap().build());

    // Try SRV _matrix._tcp.{SN} first
    debug!("Attempting to resolve {server_name} via SRV");
    if let Ok(srv) = RESOLVER
        .srv_lookup(format!("_matrix._tcp.{server_name}"))
        .await
    {
        let ips = srv
            .iter()
            .filter_map(|record| record.target().to_ip())
            .collect::<Vec<_>>();

        if !ips.is_empty() {
            debug!("Resolved {server_name} via SRV to {:?}", ips);
            return Ok(ips);
        }
    }

    // Next, try .well-known/matrix/server
    debug!("Attempting to resolve {server_name} via .well-known");
    let resp = reqwest::get(format!("https://{server_name}/.well-known/matrix/server")).await?;
    if resp.status().is_success() {
        let json: serde_json::Value = resp.json().await?;
        debug!("Received .well-known response for {server_name}: {json}");
        if let Some(target_host) = json.get("m.server")
            && let Some(target_host) = target_host.as_str()
        {
            // target_host will be in the format "hostname:port" or just "hostname"
            let hostname = target_host.split(':').next().unwrap_or(target_host);

            debug!("Extracted target host from .well-known for {server_name}: {hostname}");

            // Resolve the hostname to IPs
            let ips = RESOLVER
                .lookup_ip(hostname.into_name()?)
                .await?
                .iter()
                .collect::<Vec<_>>();

            if !ips.is_empty() {
                debug!("Resolved {server_name} via .well-known to {:?}", ips);
                return Ok(ips);
            }
        }
    }

    debug!("Failed to resolve {server_name} via .well-known, falling back to direct A/AAAA lookup");
    // Finally, just try a flat out A/AAAA lookup on the server name
    let ips = RESOLVER
        .lookup_ip(server_name.into_name()?)
        .await?
        .iter()
        .collect::<Vec<_>>();

    debug!("Resolved {server_name} via direct lookup to {:?}", ips);

    Ok(ips)
}
