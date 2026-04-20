use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
}

#[derive(Serialize)]
struct GraphqlQuery {
    query: String,
    variables: GraphqlVars,
}

#[derive(Serialize)]
struct GraphqlVars {
    package: String,
}

#[derive(Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
}

#[derive(Deserialize)]
struct GraphqlData {
    #[serde(rename = "securityVulnerabilities")]
    security_vulnerabilities: SecurityVulnerabilities,
}

#[derive(Deserialize)]
struct SecurityVulnerabilities {
    nodes: Vec<SecurityNode>,
}

#[derive(Deserialize)]
struct SecurityNode {
    advisory: AdvisoryNode,
}

#[derive(Deserialize)]
struct AdvisoryNode {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
}

pub async fn fetch_advisories(client: &Client, package: &str) -> Result<Vec<Advisory>> {
    let name = package.split('@').next().unwrap_or(package);

    let query = GraphqlQuery {
        query: r#"
            query($package: String!) {
                securityVulnerabilities(ecosystem: NPM, package: $package, first: 10) {
                    nodes {
                        advisory {
                            ghsaId
                            summary
                        }
                    }
                }
            }
        "#
        .to_string(),
        variables: GraphqlVars {
            package: name.to_string(),
        },
    };

    let resp = client
        .post("https://api.github.com/graphql")
        .header("User-Agent", "plum-scanner/0.1")
        .header("Authorization", "bearer ")
        .json(&query)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let gql: GraphqlResponse = r.json().await.unwrap_or(GraphqlResponse { data: None });
            let advisories = gql
                .data
                .map(|d| {
                    d.security_vulnerabilities
                        .nodes
                        .into_iter()
                        .map(|n| Advisory {
                            id: n.advisory.ghsa_id,
                            summary: n.advisory.summary,
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(advisories)
        }
        Err(_) => Ok(vec![]),
    }
}
