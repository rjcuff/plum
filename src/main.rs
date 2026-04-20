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
    // Header
    println!();
    println!("  {} {}", "🟣 plum".bold().purple(), format!("v{}", env!("CARGO_PKG_VERSION")).dimmed());
    println!("  {}", "─".repeat(40).dimmed());
    println!("  {} {}", "scanning".dimmed(), package.bold().white());
    println!();

    let start = Instant::now();
    let output = scanner::scan(package, config).await?;
    let elapsed = start.elapsed();

    if output.ignored {
        println!("  {} {} is in your ignore list — skipping", "○".dimmed(), package.dimmed());
        println!();
        return Ok(());
    }

    let npm = &output.npm_meta;
    let sr = &output.score_result;

    // Package info line
    if !npm.resolved_version.is_empty() {
        println!(
            "  {} {} {}",
            "pkg".dimmed(),
            package.bold(),
            format!("v{}", npm.resolved_version).purple()
        );
    }
    if npm.download_count > 0 {
        println!(
            "  {} {} downloads/week",
            "  ↓".dimmed(),
            format_downloads(npm.download_count).white()
        );
    }
    println!();

    // Checks section
    println!("  {}", "checks".dimmed());

    // CVEs
    if output.vulns.is_empty() {
        println!("  {}  No known CVEs", "✓".green().bold());
    } else {
        for v in &output.vulns {
            let sev_label = match v.severity {
                scanner::osv::VulnSeverity::Critical => "CRIT".on_red().white().bold().to_string(),
                scanner::osv::VulnSeverity::High => "HIGH".red().bold().to_string(),
                scanner::osv::VulnSeverity::Medium => "MED".yellow().to_string(),
                scanner::osv::VulnSeverity::Low => "LOW".dimmed().to_string(),
                scanner::osv::VulnSeverity::Unknown => "???".dimmed().to_string(),
            };
            println!("  {}  {} {} {}", "✗".red().bold(), sev_label, v.id.dimmed(), v.summary);
        }
    }

    // Maintainer
    if !npm.maintainer_new {
        let age_str = if npm.maintainer_age_days == 9999 {
            "established".to_string()
        } else {
            format!("{}d", npm.maintainer_age_days)
        };
        println!("  {}  Maintainer ({})", "✓".green().bold(), age_str);
    } else {
        println!(
            "  {}  New maintainer — account is {} days old",
            "▲".yellow().bold(),
            npm.maintainer_age_days
        );
    }

    // Downloads
    if npm.download_count >= 100 {
        println!("  {}  Download count healthy", "✓".green().bold());
    } else {
        println!(
            "  {}  Low downloads ({}/week)",
            "▲".yellow().bold(),
            npm.download_count
        );
    }

    // Install script
    if npm.has_install_script {
        println!(
            "  {}  Install script detected (postinstall)",
            "▲".yellow().bold()
        );
    }

    // Typosquatting
    if output.typosquat.is_suspect {
        if let Some(ref closest) = output.typosquat.closest_match {
            println!(
                "  {}  Possible typosquat of '{}'  (edit distance: {})",
                "✗".red().bold(),
                closest.red().bold(),
                output.typosquat.edit_distance
            );
        }
    }

    // Static analysis
    if !output.pattern_matches.is_empty() {
        println!();
        println!("  {}", "static analysis".dimmed());
        for p in &output.pattern_matches {
            let icon = match p.severity {
                scanner::patterns::Severity::AutoBlock => "✗".red().bold(),
                scanner::patterns::Severity::HighRisk => "▲".red().bold(),
                scanner::patterns::Severity::Warning => "▲".yellow().bold(),
            };
            println!("  {}  {} {}", icon, p.description, format!("({})", p.file).dimmed());
        }
    }

    // Score box
    println!();
    println!("  {}", "─".repeat(40).dimmed());

    let score_bar = render_score_bar(sr.score);
    println!("  {}  {}", "score".dimmed(), score_bar);

    let verdict_str = match sr.verdict {
        Verdict::Safe => format!("{}/100 {}", sr.score, "SAFE".green().bold()),
        Verdict::Risky => format!("{}/100 {}", sr.score, "RISKY".yellow().bold()),
        Verdict::Dangerous => format!("{}/100 {}", sr.score, "DANGEROUS".red().bold()),
    };
    println!("  {}  {}", "     ".dimmed(), verdict_str);
    println!("  {}  {}", "time".dimmed(), format!("{:.2}s", elapsed.as_secs_f64()).dimmed());

    if sr.hard_blocked {
        println!();
        println!("  {} {}", "✗".red().bold(), "Blocked — will not install.".red().bold());
        println!();
        return Ok(());
    }

    println!();

    if !do_install {
        return Ok(());
    }

    // Install gate
    let passes = sr.score >= config.threshold as i32;
    if !passes {
        println!(
            "  {} Score {}/100 is below threshold {}. Will not install.",
            "✗".red().bold(),
            sr.score,
            config.threshold
        );
        println!();
        return Ok(());
    }

    if force_yes || config.auto_install_above_threshold {
        npm_install(package)?;
    } else {
        print!("  Install? (y/n) ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("y") {
            npm_install(package)?;
        } else {
            println!("  Aborted.");
        }
    }

    println!();
    Ok(())
}

fn render_score_bar(score: i32) -> String {
    let width = 20;
    let filled = ((score as f64 / 100.0) * width as f64).round() as usize;
    let empty = width - filled;

    let bar_color = if score >= 70 {
        format!("{}", "█".repeat(filled).green())
    } else if score >= 35 {
        format!("{}", "█".repeat(filled).yellow())
    } else {
        format!("{}", "█".repeat(filled).red())
    };

    format!("{}{}", bar_color, "░".repeat(empty).dimmed())
}

fn npm_install(package: &str) -> Result<()> {
    println!();
    println!("  {} npm install {}", "→".cyan().bold(), package);
    let status = Command::new("npm").args(["install", package]).status()?;
    if !status.success() {
        anyhow::bail!("npm install failed");
    }
    Ok(())
}

fn format_downloads(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
