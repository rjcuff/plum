pub mod advisory;
pub mod npm;
pub mod osv;
pub mod patterns;
pub mod score;
pub mod tarball;
pub mod typosquat;

use crate::config::Config;
use anyhow::Result;
use reqwest::Client;
use std::collections::HashSet;

pub async fn scan(package: &str, config: &Config) -> Result<ScanOutput> {
    let pkg_name = package.split('@').next().unwrap_or(package);

    if config.ignore.iter().any(|p| p == pkg_name) {
        return Ok(ScanOutput::ignored(package));
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let typosquat_result = typosquat::check(pkg_name);

    // Fetch npm metadata first to get the resolved version
    let (npm_res, advisory_res) = tokio::join!(
        npm::fetch_metadata(&client, package),
        advisory::fetch_advisories(&client, package),
    );

    let npm_meta = npm_res?;
    let _advisories = advisory_res.unwrap_or_default();

    // Now query OSV with the resolved version so we only get CVEs affecting this version
    let resolved = if npm_meta.resolved_version.is_empty() {
        None
    } else {
        Some(npm_meta.resolved_version.as_str())
    };
    let vulns = osv::fetch_vulnerabilities(&client, package, resolved)
        .await
        .unwrap_or_default();

    // Tarball fetch starts immediately after we have the URL (as early as possible)
    let js_files = if !npm_meta.tarball_url.is_empty() {
        tarball::fetch_and_scan(&client, &npm_meta.tarball_url)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    let all_patterns = deduplicated_patterns(&js_files);
    let result = score::compute(&vulns, &npm_meta, &all_patterns, typosquat_result.is_suspect, config);

    Ok(ScanOutput {
        package: package.to_string(),
        score_result: result,
        npm_meta,
        vulns,
        pattern_matches: all_patterns,
        typosquat: typosquat_result,
        ignored: false,
    })
}

fn deduplicated_patterns(js_files: &[tarball::JsFile]) -> Vec<patterns::PatternMatch> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut result = Vec::new();

    for file in js_files {
        let matches = patterns::scan_content(&file.path, &file.content).unwrap_or_default();
        for m in matches {
            let key = format!("{}:{}", m.description, file.path);
            if seen.insert(key) {
                result.push(m);
            }
        }
    }

    // Cap high-volume patterns (e.g. exec) at 3 occurrences across files
    let mut desc_counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    result.retain(|m| {
        let count = desc_counts.entry(m.description).or_insert(0);
        *count += 1;
        *count <= 3
    });

    result
}

pub struct ScanOutput {
    pub package: String,
    pub score_result: score::ScoreResult,
    pub npm_meta: npm::NpmMeta,
    pub vulns: Vec<osv::Vulnerability>,
    pub pattern_matches: Vec<patterns::PatternMatch>,
    pub typosquat: typosquat::TyposquatResult,
    pub ignored: bool,
}

impl ScanOutput {
    fn ignored(package: &str) -> Self {
        Self {
            package: package.to_string(),
            score_result: score::ScoreResult {
                score: 100,
                verdict: score::Verdict::Safe,
                signals: vec![],
                hard_blocked: false,
            },
            npm_meta: npm::NpmMeta::default(),
            vulns: vec![],
            pattern_matches: vec![],
            typosquat: typosquat::TyposquatResult {
                is_suspect: false,
                closest_match: None,
                edit_distance: 0,
            },
            ignored: true,
        }
    }
}
