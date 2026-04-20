use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NpmMeta {
    pub tarball_url: String,
    pub published_recently: bool,
    pub maintainer_new: bool,
    pub has_readme: bool,
    pub has_install_script: bool,
    pub download_count: u64,
    pub maintainer_age_days: i64,
    pub published_days_ago: i64,
}

impl Default for NpmMeta {
    fn default() -> Self {
        Self {
            tarball_url: String::new(),
            published_recently: false,
            maintainer_new: false,
            has_readme: true,
            has_install_script: false,
            download_count: 0,
            maintainer_age_days: 9999,
            published_days_ago: 9999,
        }
    }
}

#[derive(Deserialize)]
struct NpmPackage {
    #[serde(default)]
    readme: String,
    #[serde(default)]
    versions: HashMap<String, NpmVersion>,
    // npm includes "created" and "modified" keys alongside version timestamps
    // so we use Value instead of String to avoid deserialization failures
    #[serde(default)]
    time: HashMap<String, Value>,
    #[serde(rename = "dist-tags", default)]
    dist_tags: HashMap<String, String>,
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
}

#[derive(Deserialize)]
struct NpmVersion {
    dist: NpmDist,
    #[serde(default)]
    scripts: HashMap<String, String>,
}

#[derive(Deserialize)]
struct NpmDist {
    tarball: String,
}

#[derive(Deserialize)]
struct NpmMaintainer {
    name: String,
}

#[derive(Deserialize)]
struct NpmDownloads {
    #[serde(default)]
    downloads: u64,
}

#[derive(Deserialize)]
struct NpmUserCreated {
    created: Option<String>,
}

pub async fn fetch_metadata(client: &Client, package: &str) -> Result<NpmMeta> {
    let (name, version_hint) = split_package(package);

    let resp = client
        .get(format!("https://registry.npmjs.org/{}", name))
        .send()
        .await?;

    let status = resp.status();
    let raw: Value = resp.json().await?;

    if status == 404 || raw.get("error").is_some() {
        anyhow::bail!("package '{}' not found on npm", name);
    }

    let pkg: NpmPackage = serde_json::from_value(raw)?;

    let version = version_hint
        .unwrap_or_else(|| pkg.dist_tags.get("latest").cloned().unwrap_or_default());

    let (tarball_url, has_install_script) = pkg
        .versions
        .get(&version)
        .map(|ver| {
            let scripts = &ver.scripts;
            let install_script = scripts.contains_key("postinstall")
                || scripts.contains_key("install")
                || scripts.contains_key("preinstall");
            (ver.dist.tarball.clone(), install_script)
        })
        .unwrap_or_default();

    let has_readme = !pkg.readme.is_empty();

    let now = Utc::now();

    let published_days_ago = pkg
        .time
        .get(&version)
        .and_then(|v| v.as_str())
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| (now - t.with_timezone(&Utc)).num_days())
        .unwrap_or(9999);
    let published_recently = published_days_ago < 7;

    let maintainer_age_days =
        fetch_maintainer_age(client, &pkg.maintainers).await.unwrap_or(9999);
    let maintainer_new = maintainer_age_days < 30;

    let download_count = fetch_downloads(client, name).await.unwrap_or(0);

    Ok(NpmMeta {
        tarball_url,
        published_recently,
        maintainer_new,
        has_readme,
        has_install_script,
        download_count,
        maintainer_age_days,
        published_days_ago,
    })
}

async fn fetch_maintainer_age(client: &Client, maintainers: &[NpmMaintainer]) -> Result<i64> {
    let username = maintainers
        .first()
        .map(|m| m.name.as_str())
        .unwrap_or("");
    if username.is_empty() {
        return Ok(9999);
    }

    let resp = client
        .get(format!("https://registry.npmjs.org/-/user/org.couchdb.user/{}", username))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(9999);
    }

    let user: NpmUserCreated = resp.json().await.unwrap_or(NpmUserCreated { created: None });
    let age = user
        .created
        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| (Utc::now() - t.with_timezone(&Utc)).num_days())
        .unwrap_or(9999);

    Ok(age)
}

async fn fetch_downloads(client: &Client, name: &str) -> Result<u64> {
    let resp = client
        .get(format!(
            "https://api.npmjs.org/downloads/point/last-week/{}",
            name
        ))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Ok(0);
    }

    let dl: NpmDownloads = resp.json().await.unwrap_or(NpmDownloads { downloads: 0 });
    Ok(dl.downloads)
}

fn split_package(package: &str) -> (&str, Option<String>) {
    if let Some(at) = package.rfind('@') {
        if at > 0 {
            return (&package[..at], Some(package[at + 1..].to_string()));
        }
    }
    (package, None)
}
