use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: VulnSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
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
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    score_type: String,
    #[serde(default)]
    score: String,
}

#[derive(Deserialize)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
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
        .map(|v| {
            let severity = parse_severity(&v);
            Vulnerability {
                id: v.id,
                summary: v.summary,
                severity,
            }
        })
        .collect())
}

fn parse_severity(vuln: &OsvVuln) -> VulnSeverity {
    // Try CVSS score first
    for s in &vuln.severity {
        if s.score_type == "CVSS_V3" || s.score_type == "CVSS_V2" {
            if let Some(score) = extract_cvss_score(&s.score) {
                return cvss_to_severity(score);
            }
        }
    }

    // Fall back to database_specific severity string
    if let Some(ref db) = vuln.database_specific {
        if let Some(ref sev) = db.severity {
            return match sev.to_uppercase().as_str() {
                "CRITICAL" => VulnSeverity::Critical,
                "HIGH" => VulnSeverity::High,
                "MODERATE" | "MEDIUM" => VulnSeverity::Medium,
                "LOW" => VulnSeverity::Low,
                _ => VulnSeverity::Unknown,
            };
        }
    }

    VulnSeverity::Unknown
}

fn extract_cvss_score(vector: &str) -> Option<f64> {
    // CVSS vectors look like "CVSS:3.1/AV:N/AC:L/..." but some entries are just a number
    if let Ok(score) = vector.parse::<f64>() {
        return Some(score);
    }
    None
}

fn cvss_to_severity(score: f64) -> VulnSeverity {
    if score >= 9.0 {
        VulnSeverity::Critical
    } else if score >= 7.0 {
        VulnSeverity::High
    } else if score >= 4.0 {
        VulnSeverity::Medium
    } else {
        VulnSeverity::Low
    }
}

fn strip_version(package: &str) -> &str {
    package.split('@').next().unwrap_or(package)
}
