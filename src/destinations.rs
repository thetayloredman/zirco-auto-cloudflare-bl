/// Fetch all of the destinations from the Synapse admin API.
pub async fn get_destinations() -> Vec<String> {
    let api = std::env::var("HOMESERVER").expect("HOMESERVER environment variable must be set");
    let token = std::env::var("TOKEN").expect("TOKEN environment variable must be set");

    let client = reqwest::Client::new();
    let url = format!("{api}/_synapse/admin/v1/federation/destinations?limit=10000");

    let mut destinations = Vec::new();
    let mut next_token = None::<String>;

    loop {
        // cursed
        let url = if let Some(ref token) = next_token {
            format!("{}&from={}", url, token)
        } else {
            url.clone()
        };

        let req = client.get(&url).bearer_auth(&token);

        let resp = req.send().await.expect("Failed to fetch destinations");
        if !resp.status().is_success() {
            panic!("Failed to fetch destinations: HTTP {}", resp.status());
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .expect("Failed to parse destinations response");
        if let Some(dest_array) = json.get("destinations").and_then(|d| d.as_array()) {
            for dest in dest_array {
                if let Some(dest) = dest.get("destination")
                    && let Some(dest_str) = dest.as_str()
                {
                    destinations.push(dest_str.to_string());
                }
            }
        }

        next_token = json
            .get("next_token")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    destinations
}
