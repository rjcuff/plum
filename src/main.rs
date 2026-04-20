mod config;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use config::Config;
use scanner::score::Verdict;
use std::io::{self, Write};
use std::process::Command;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "plum", version, about = "npm supply chain security scanner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Package to scan (e.g. lodash or lodash@4.17.21)
    package: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan then install if score passes threshold
    Install {
        /// Package to install
        package: String,

        /// Auto-approve install without prompting
        #[arg(short, long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load()?;

    match cli.command {
        Some(Commands::Install { package, yes }) => {
            run_scan(&package, &config, true, yes).await?;
        }
        None => {
            let package = cli.package.ok_or_else(|| {
                anyhow::anyhow!("Usage: plum <package>  or  plum install <package>")
            })?;
            run_scan(&package, &config, false, false).await?;
        }
    }

    Ok(())
}

async fn run_scan(package: &str, config: &Config, do_install: bool, force_yes: bool) -> Result<()> {
    println!("\n{} {}\n", "plum".bold().purple(), package.bold());

    let start = Instant::now();
    let output = scanner::scan(package, config).await?;
    let elapsed = start.elapsed();

    if output.ignored {
        println!("{} {} is in your ignore list — skipping", "○".dimmed(), package.dimmed());
        return Ok(());
    }

    // Show resolved version
    if !output.npm_meta.resolved_version.is_empty() {
        println!("{} Resolved version: {}", "→".cyan(), output.npm_meta.resolved_version);
    }

    let sr = &output.score_result;

    // CVEs
    if output.vulns.is_empty() {
        println!("{} No known CVEs", "✓".green().bold());
    } else {
        for v in &output.vulns {
            let sev_label = match v.severity {
                scanner::osv::VulnSeverity::Critical => "CRITICAL".red().bold().to_string(),
                scanner::osv::VulnSeverity::High => "HIGH".red().to_string(),
                scanner::osv::VulnSeverity::Medium => "MEDIUM".yellow().to_string(),
                scanner::osv::VulnSeverity::Low => "LOW".dimmed().to_string(),
                scanner::osv::VulnSeverity::Unknown => "UNKNOWN".dimmed().to_string(),
            };
            println!("{} {} [{}] — {}", "✗".red().bold(), v.id.red(), sev_label, v.summary);
        }
    }

    // Maintainer age
    let npm = &output.npm_meta;
    if !npm.maintainer_new {
        let age_str = if npm.maintainer_age_days == 9999 {
            "established".to_string()
        } else {
            format!("{} days", npm.maintainer_age_days)
        };
        println!("{} Established maintainer ({})", "✓".green().bold(), age_str);
    } else {
        println!(
            "{} New maintainer ({} days old)",
            "!".yellow().bold(),
            npm.maintainer_age_days
        );
    }

    // Downloads
    if npm.download_count >= 100 {
        println!(
            "{} {} weekly downloads",
            "✓".green().bold(),
            format_downloads(npm.download_count)
        );
    } else {
        println!(
            "{} Low downloads ({} last week)",
            "!".yellow().bold(),
            npm.download_count
        );
    }

    // Install script
    if npm.has_install_script {
        println!(
            "{} Contains install script — review postinstall hook",
            "■".yellow().bold()
        );
    }

    // Typosquatting
    if output.typosquat.is_suspect {
        if let Some(ref closest) = output.typosquat.closest_match {
            println!(
                "{} Name is {} edit(s) away from '{}' — possible typosquatting",
                "!".red().bold(),
                output.typosquat.edit_distance,
                closest.red()
            );
        }
    }

    // Static analysis pattern matches
    for p in &output.pattern_matches {
        let icon = match p.severity {
            scanner::patterns::Severity::AutoBlock => "✗".red().bold(),
            scanner::patterns::Severity::HighRisk => "!".red().bold(),
            scanner::patterns::Severity::Warning => "■".yellow().bold(),
        };
        println!("{} {} ({})", icon, p.description, p.file.dimmed());
    }

    // Score line
    println!();
    let score_str = format!("Score: {}/100", sr.score);
    let verdict_line = match sr.verdict {
        Verdict::Safe => format!("{} — {}", score_str, "SAFE".green().bold()),
        Verdict::Risky => format!("{} — {}", score_str, "RISKY".yellow().bold()),
        Verdict::Dangerous => format!("{} — {}", score_str, "DANGEROUS".red().bold()),
    };
    println!("{}", verdict_line);
    println!("{}", format!("Scanned in {:.2}s", elapsed.as_secs_f64()).dimmed());

    if sr.hard_blocked {
        println!("{}", "Blocked. Will not install.".red());
        return Ok(());
    }

    if !do_install {
        return Ok(());
    }

    // Install gate: score must meet threshold
    let passes = sr.score >= config.threshold as i32;
    if !passes {
        println!(
            "{} Score {}/100 is below threshold {}. Will not install.",
            "✗".red().bold(),
            sr.score,
            config.threshold
        );
        return Ok(());
    }

    if force_yes || config.auto_install_above_threshold {
        npm_install(package)?;
    } else {
        print!("Install? (y/n) ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("y") {
            npm_install(package)?;
        } else {
            println!("Aborted.");
        }
    }

    Ok(())
}

fn npm_install(package: &str) -> Result<()> {
    println!("\n{} npm install {}", "→".cyan().bold(), package);
    let status = Command::new("npm").args(["install", package]).status()?;
    if !status.success() {
        anyhow::bail!("npm install failed");
    }
    Ok(())
}

fn format_downloads(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.0}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
