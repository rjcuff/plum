use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
}

pub async fn fetch_vulnerabilities(client: &Client, package: &str) -> Result<Vec<Vulnerability>> {
    let name = strip_version(package);
    let body = OsvQuery {
        package: OsvPackage {
            name: name.to_string(),
            ecosystem: "npm".to_string(),
        },
    };

    let resp: OsvResponse = client
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    Ok(resp
        .vulns
        .into_iter()
        .map(|v| Vulnerability {
            id: v.id,
            summary: v.summary,
        })
        .collect())
}

fn strip_version(package: &str) -> &str {
    package.split('@').next().unwrap_or(package)
}
