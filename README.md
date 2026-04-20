# plum

**npm supply chain security scanner — scan before you install.**

```
plum lodash@4.17.21

✓ No known CVEs
✓ Established maintainer (8 years)
✓ 47M weekly downloads
■ Contains install script — review postinstall hook

Score: 82/100 — SAFE
Scanned in 0.54s
```

## Install

**via npm** (recommended — works everywhere Node is installed):
```bash
npm install -g @rjcuff/plum
```

**via curl** (macOS / Linux):
```bash
curl -fsSL https://raw.githubusercontent.com/rjcuff/plum/main/install.sh | bash
```

Or download a binary directly from [Releases](https://github.com/rjcuff/plum/releases).

## Usage

```bash
# Scan a package before deciding to install
plum <package>

# Scan then install if it passes your threshold
plum install <package>

# Auto-approve without prompting
plum install <package> --yes
```

## What it checks

| Signal | Score impact |
|--------|-------------|
| Known CVE found | Hard block (score → 0) |
| Published < 7 days ago | −20 pts |
| Maintainer account < 30 days old | −20 pts |
| No README present | −10 pts |
| Install scripts (postinstall) | −15 pts |
| Download count < 100/week | −10 pts |
| Name within edit-distance 2 of top-200 package | −30 pts |
| Malicious code patterns in .js files | −5 to hard block |

Packages score 0–100. Score ≥ threshold = SAFE. Below = RISKY or DANGEROUS.

## Data sources

- **[OSV](https://osv.dev)** — Google's open vulnerability database (all npm CVEs)
- **npm Registry** — publish date, maintainer age, download counts, install scripts
- **GitHub Advisory** — known malicious package database
- **Tarball static analysis** — downloads and scans `.js` files in memory, never to disk

All checks run in parallel. Typical scan time: **< 1 second**.

## Config

Drop a `plum.json` in your project root:

```json
{
  "threshold": 70,
  "block_on_cve": true,
  "auto_install_above_threshold": false,
  "ignore": ["my-internal-package"]
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `threshold` | `70` | Minimum score to pass |
| `block_on_cve` | `true` | Hard-block on any known CVE |
| `auto_install_above_threshold` | `false` | Install without prompting if score passes |
| `ignore` | `[]` | Package names to skip scanning |

## Build from source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/rjcuff/plum
cd plum
cargo build --release
```

## Why plum

Supply chain attacks happen *after* you run `npm install`. plum intercepts before. It takes < 1 second and requires no account, no API key, and no workflow change.

Comparable tools: [Socket.dev](https://socket.dev) ($20M raised). plum is open source, CLI-first, and free.

## License

[Elastic License 2.0](./LICENSE) — source available, free to use personally and commercially as a CLI tool. You may not offer plum as a hosted or managed service without permission. Pull requests and bug reports welcome.
