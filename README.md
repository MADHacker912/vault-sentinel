# 🛡️ VaultSentinel

<p align="center">
  <strong>⚡ Ultra-fast, zero-dependency secret leak & Shannon entropy scanner for Git repositories with offline interactive HTML threat reports.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-%3E%3D16.0.0-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js" />
  <img src="https://img.shields.io/badge/Dependencies-0%20(Pure%20Stdlib)-brightgreen?style=flat-square" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/Security-Pre--Commit%20Gate-red?style=flat-square" alt="Pre Commit" />
  <img src="https://img.shields.io/badge/Coverage-35%2B%20Detectors-cyan?style=flat-square" alt="Detectors" />
</p>

---

```
╦  ╦╔═╗╦ ╦╦  ╔╦╗  ╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦  
╚╗╔╝╠═╣║ ║║   ║   ╚═╗║╣ ║║║ ║ ║║║║║╣ ║  
 ╚╝ ╩ ╩╚═╝╩═╝ ╩   ╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝
⚡ High-Precision Secret Leak & Entropy Scanner for Git Repositories
```

Accidentally committing credentials to public repositories is one of the most common causes of infrastructure breaches. **VaultSentinel** intercepts leaked secrets before they reach your remote origin, using a hybrid engine of **high-fidelity pattern matching** and **Shannon entropy heuristics**.

---

## ⚡ Key Highlights

- **Zero Runtime Dependencies**: Written entirely in pure, modern Node.js using native standard library modules. Instant startup, zero supply-chain risk.
- **Shannon Entropy Heuristics**: Catches novel, obfuscated, and unclassified high-randomness tokens that static regex signatures fail to spot.
- **Git Native Integration**:
  - Scan staged changes in milliseconds before making a commit.
  - Audit entire commit histories (`--history 50`).
  - Install a 1-click automated Git `pre-commit` hook.
- **Interactive Dark-Glass HTML Report**: Generates an offline, standalone single-file HTML audit dashboard with risk metrics, search filters, and severity tags.
- **Masked Previews**: Masks sensitive credentials (`sk-proj-****...1234`) in terminal and HTML reports so the audit tool itself never leaks secrets.
- **CI/CD Ready**: Includes `--strict` mode returning non-zero exit codes for GitHub Actions, GitLab CI, and deployment pipelines.

---

## 🚀 Quickstart

Run directly without installation via `npx`:

```bash
# Scan current repository
npx vault-sentinel scan .

# Scan and export an interactive HTML security dashboard
npx vault-sentinel scan . --html audit-report.html

# Scan only staged files before git commit
npx vault-sentinel scan --staged

# Deep audit through the last 50 commits
npx vault-sentinel scan --history 50
```

### 🔒 1-Click Git Pre-Commit Hook

Install VaultSentinel directly into your local `.git/hooks`:

```bash
npx vault-sentinel install-hook
```

Now any `git commit` command will automatically verify that staged files do not contain exposed credentials.

---

## 🔍 Detection Matrix

VaultSentinel ships with precision detectors for 35+ industry credentials:

| Category | Detected Signatures & Patterns |
| :--- | :--- |
| **Cloud Providers** | AWS Access Key IDs (`AKIA...`), AWS Secret Keys, Google Cloud Platform Keys (`AIza...`), GCP OAuth Secrets |
| **AI & LLM Services** | OpenAI (`sk-...`, `sk-proj-...`), Anthropic Claude (`sk-ant-...`), HuggingFace tokens (`hf_...`) |
| **Code Repositories** | GitHub PATs (`ghp_...`, `github_pat_...`), GitLab Tokens (`glpat-...`) |
| **Payment Gateways** | Stripe Live Secret Keys (`sk_live_...`), Stripe Restricted Keys (`rk_live_...`) |
| **Messaging & Bots** | Discord Bot Tokens, Telegram Bot Tokens, Slack Bot/User Tokens, Slack Incoming Webhooks, Twilio SIDs |
| **Cryptography** | RSA, OpenSSH, EC, DSA, and PGP Private Armor Key Blocks |
| **Databases** | Cleartext connection URIs (`postgres://`, `mongodb://`, `mysql://`, `redis://`) |
| **Package Registries**| NPM Automation Tokens (`npm_...`), PyPI Upload Tokens |
| **Heuristics** | Shannon Entropy Anomaly Detection for high-randomness secrets ($H \ge 4.30$) |

---

## 📊 Interactive HTML Report

Exporting with `--html report.html` builds an offline, zero-network dashboard:

```bash
npx vault-sentinel scan . --html security-report.html
```

- **Live Search & Filter**: Instant filtering by `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` severity.
- **Exact Coordinates**: Line and column numbers mapped to affected files.
- **Safe Previews**: Masked tokens ensure safety during team reviews and presentations.

---

## 🛠️ CLI Options & Reference

```
Usage:
  vault-sentinel [command] [options]

Commands:
  scan [path]           Scan a folder or repository (defaults to current dir)
  install-hook          Install VaultSentinel as a local git pre-commit hook

Options:
  --staged              Scan only staged git changes (fast pre-commit check)
  --history [n]         Scan through the last [n] git commits (default: 20)
  --html [file]         Export standalone dark-glass HTML audit report
  --no-entropy          Disable Shannon entropy anomaly detection
  --strict              Exit with code 1 if any leak is detected (for CI/CD)
  -v, --version         Show version
  -h, --help            Show help menu
```

---

## 🤖 GitHub Actions Integration

Drop this snippet into `.github/workflows/security.yml`:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  vault-sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Run Secret Audit
        run: npx vault-sentinel scan . --strict --html report.html
      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vault-sentinel-report
          path: report.html
```

---

## 🧪 Testing

Run the included unit test suite:

```bash
npm test
```

---

## 📜 License

Distributed under the [MIT License](LICENSE). Built with precision by [MADHacker912](https://github.com/MADHacker912).
