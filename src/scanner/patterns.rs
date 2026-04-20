use anyhow::Result;
use regex::RegexSet;

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    AutoBlock,
    HighRisk,
    Warning,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub description: &'static str,
    pub severity: Severity,
    pub file: String,
}

static PATTERN_DEFS: &[(&str, &str, Severity)] = &[
    (
        r"eval\s*\(\s*Buffer\.from",
        "Obfuscated base64 eval — likely malicious",
        Severity::AutoBlock,
    ),
    (
        r"process\.env\.npm_token",
        "Credential harvesting (npm_token)",
        Severity::HighRisk,
    ),
    (
        r#"fs\.writeFile\s*\(\s*['"/]etc/"#,
        "Writing to system paths",
        Severity::HighRisk,
    ),
    (
        r#"require\s*\(\s*['"]child_process['"]"#,
        "Shell access via child_process",
        Severity::Warning,
    ),
    (
        r"\bexec\s*\(",
        "Shell execution (exec)",
        Severity::Warning,
    ),
    (
        r#"fetch\s*\(\s*['"]http://"#,
        "Outbound HTTP in install script",
        Severity::Warning,
    ),
];

pub fn scan_content(filename: &str, content: &str) -> Result<Vec<PatternMatch>> {
    let patterns: Vec<&str> = PATTERN_DEFS.iter().map(|(p, _, _)| *p).collect();
    let set = RegexSet::new(&patterns)?;

    let matches: Vec<PatternMatch> = set
        .matches(content)
        .into_iter()
        .map(|i| {
            let (_, desc, sev) = &PATTERN_DEFS[i];
            PatternMatch {
                description: desc,
                severity: sev.clone(),
                file: filename.to_string(),
            }
        })
        .collect();

    Ok(matches)
}
