use crate::config::Config;
use crate::scanner::npm::NpmMeta;
use crate::scanner::osv::{Vulnerability, VulnSeverity};
use crate::scanner::patterns::{PatternMatch, Severity};

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Safe,
    Risky,
    Dangerous,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Safe => "SAFE",
            Verdict::Risky => "RISKY",
            Verdict::Dangerous => "DANGEROUS",
        }
    }
}

#[derive(Debug)]
pub struct Signal {
    pub description: String,
    pub points: i32,
}

pub struct ScoreResult {
    pub score: i32,
    pub verdict: Verdict,
    pub signals: Vec<Signal>,
    pub hard_blocked: bool,
}

pub fn compute(
    vulns: &[Vulnerability],
    npm: &NpmMeta,
    patterns: &[PatternMatch],
    typosquat: bool,
    config: &Config,
) -> ScoreResult {
    let mut score: i32 = 100;
    let mut signals = Vec::new();
    let mut hard_blocked = false;

    let min_sev = parse_min_severity(&config.min_cve_severity);
    let serious_vulns: Vec<&Vulnerability> = vulns
        .iter()
        .filter(|v| severity_rank(&v.severity) >= severity_rank(&min_sev))
        .collect();

    if !serious_vulns.is_empty() && config.block_on_cve {
        hard_blocked = true;
        score = 0;
        signals.push(Signal {
            description: format!(
                "{} CVE(s) at {} severity or above (of {} total)",
                serious_vulns.len(),
                config.min_cve_severity.to_uppercase(),
                vulns.len()
            ),
            points: -100,
        });
        return ScoreResult {
            score,
            verdict: Verdict::Dangerous,
            signals,
            hard_blocked,
        };
    }

    // Still deduct for serious CVEs even if not hard-blocking
    if !serious_vulns.is_empty() {
        let pts = -30;
        score += pts;
        signals.push(Signal {
            description: format!(
                "{} CVE(s) at {} severity or above",
                serious_vulns.len(),
                config.min_cve_severity.to_uppercase()
            ),
            points: pts,
        });
    }

    // Minor deduction for lower-severity CVEs
    let minor_count = vulns.len() - serious_vulns.len();
    if minor_count > 0 {
        let pts = -5;
        score += pts;
        signals.push(Signal {
            description: format!("{} lower-severity CVE(s) (below threshold)", minor_count),
            points: pts,
        });
    }

    let auto_block = patterns.iter().any(|p| p.severity == Severity::AutoBlock);
    if auto_block {
        hard_blocked = true;
        score = 0;
        signals.push(Signal {
            description: "Obfuscated base64 eval detected — auto blocked".to_string(),
            points: -100,
        });
        return ScoreResult {
            score,
            verdict: Verdict::Dangerous,
            signals,
            hard_blocked,
        };
    }

    if npm.published_recently {
        let pts = -20;
        score += pts;
        signals.push(Signal {
            description: format!("Published {} days ago (< 7 days)", npm.published_days_ago),
            points: pts,
        });
    }

    if npm.maintainer_new {
        let pts = -20;
        score += pts;
        signals.push(Signal {
            description: format!(
                "Maintainer account {} days old (< 30 days)",
                npm.maintainer_age_days
            ),
            points: pts,
        });
    }

    if !npm.has_readme {
        let pts = -10;
        score += pts;
        signals.push(Signal {
            description: "No README present".to_string(),
            points: pts,
        });
    }

    if npm.has_install_script {
        let pts = -15;
        score += pts;
        signals.push(Signal {
            description: "Install script present (postinstall/install/preinstall)".to_string(),
            points: pts,
        });
    }

    if npm.download_count < 100 {
        let pts = -10;
        score += pts;
        signals.push(Signal {
            description: format!("Low download count ({} last week)", npm.download_count),
            points: pts,
        });
    }

    if typosquat {
        let pts = -30;
        score += pts;
        signals.push(Signal {
            description: "Name suspiciously similar to popular package (typosquatting risk)".to_string(),
            points: pts,
        });
    }

    for p in patterns {
        if p.severity != Severity::AutoBlock {
            let pts = match p.severity {
                Severity::HighRisk => -15,
                Severity::Warning => -5,
                Severity::AutoBlock => 0,
            };
            score += pts;
            signals.push(Signal {
                description: format!("{} in {}", p.description, p.file),
                points: pts,
            });
        }
    }

    score = score.max(0).min(100);

    let verdict = if score >= config.threshold as i32 {
        Verdict::Safe
    } else if score >= (config.threshold as i32 / 2) {
        Verdict::Risky
    } else {
        Verdict::Dangerous
    };

    ScoreResult {
        score,
        verdict,
        signals,
        hard_blocked,
    }
}

fn severity_rank(sev: &VulnSeverity) -> u8 {
    match sev {
        VulnSeverity::Critical => 4,
        VulnSeverity::High => 3,
        VulnSeverity::Medium => 2,
        VulnSeverity::Low => 1,
        VulnSeverity::Unknown => 0,
    }
}

fn parse_min_severity(s: &str) -> VulnSeverity {
    match s.to_lowercase().as_str() {
        "critical" => VulnSeverity::Critical,
        "high" => VulnSeverity::High,
        "medium" | "moderate" => VulnSeverity::Medium,
        "low" => VulnSeverity::Low,
        _ => VulnSeverity::High,
    }
}
