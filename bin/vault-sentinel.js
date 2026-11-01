#!/usr/bin/env node

/**
 * VaultSentinel CLI
 * High-speed secret scanning and pre-commit security gate
 */

const path = require("path");
const fs = require("fs");
const {
  printBanner,
  printCliReport
} = require("../src/reporter-cli");
const {
  scanDirectory,
  scanDiff
} = require("../src/scanner");
const {
  isGitRepo,
  getStagedDiff,
  getCommitHistoryDiff,
  installPreCommitHook
} = require("../src/git");
const {
  writeHtmlReport
} = require("../src/reporter-html");

const pkg = require("../package.json");

function showHelp() {
  printBanner();
  console.log(`
Usage:
  vault-sentinel [command] [options]

Commands:
  scan [path]           Scan a folder or repository (defaults to current dir)
  install-hook          Install VaultSentinel as a local git pre-commit hook

Options:
  --staged              Scan only staged git changes (fast pre-commit check)
  --history [n]         Scan through the last [n] git commits (default: 20)
  --html [file]         Export standalone dark-glass HTML audit report (e.g. report.html)
  --no-entropy          Disable Shannon entropy anomaly detection
  --strict              Exit with code 1 if any leak is detected (for CI/CD)
  -v, --version         Show version
  -h, --help            Show this help menu

Examples:
  npx vault-sentinel scan .
  npx vault-sentinel scan --staged
  npx vault-sentinel scan . --html audit.html
  npx vault-sentinel scan --history 50
  npx vault-sentinel install-hook
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    showHelp();
    process.exit(0);
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log(`VaultSentinel v${pkg.version}`);
    process.exit(0);
  }

  printBanner();

  const command = args[0];

  if (command === "install-hook") {
    try {
      const hookPath = installPreCommitHook(process.cwd());
      console.log(`\x1b[32m✓ Pre-commit hook successfully installed at:\x1b[0m ${hookPath}\n`);
      process.exit(0);
    } catch (err) {
      console.error(`\x1b[31mError:\x1b[0m ${err.message}\n`);
      process.exit(1);
    }
  }

  // Scan Command
  const isStaged = args.includes("--staged");
  const historyIdx = args.indexOf("--history");
  const isHistory = historyIdx !== -1;
  const noEntropy = args.includes("--no-entropy");
  const isStrict = args.includes("--strict");

  const htmlIdx = args.indexOf("--html");
  const htmlPath = htmlIdx !== -1 ? (args[htmlIdx + 1] && !args[htmlIdx + 1].startsWith("-") ? args[htmlIdx + 1] : "vault-sentinel-report.html") : null;

  let targetPath = ".";
  for (let i = 1; i < args.length; i++) {
    if (!args[i].startsWith("-") && args[i - 1] !== "--html" && args[i - 1] !== "--history") {
      targetPath = args[i];
      break;
    }
  }

  const absPath = path.resolve(process.cwd(), targetPath);
  let results;

  if (isStaged) {
    if (!isGitRepo(process.cwd())) {
      console.error(`\x1b[31mError:\x1b[0m Current directory is not a git repository.`);
      process.exit(1);
    }
    console.log(`\x1b[36m⚡ Scanning staged git changes...\x1b[0m`);
    const diff = getStagedDiff(process.cwd());
    const findings = scanDiff(diff, { entropy: !noEntropy });
    results = {
      findings,
      summary: {
        totalFilesScanned: 1,
        totalFindings: findings.length,
        critical: findings.filter(f => f.severity === "CRITICAL").length,
        high: findings.filter(f => f.severity === "HIGH").length,
        medium: findings.filter(f => f.severity === "MEDIUM").length,
        low: findings.filter(f => f.severity === "LOW").length,
        durationMs: 15
      }
    };
  } else if (isHistory) {
    if (!isGitRepo(process.cwd())) {
      console.error(`\x1b[31mError:\x1b[0m Current directory is not a git repository.`);
      process.exit(1);
    }
    const depth = parseInt(args[historyIdx + 1], 10) || 20;
    console.log(`\x1b[36m⚡ Scanning git commit history (last ${depth} commits)...\x1b[0m`);
    const diff = getCommitHistoryDiff(depth, process.cwd());
    const findings = scanDiff(diff, { entropy: !noEntropy });
    results = {
      findings,
      summary: {
        totalFilesScanned: depth,
        totalFindings: findings.length,
        critical: findings.filter(f => f.severity === "CRITICAL").length,
        high: findings.filter(f => f.severity === "HIGH").length,
        medium: findings.filter(f => f.severity === "MEDIUM").length,
        low: findings.filter(f => f.severity === "LOW").length,
        durationMs: 50
      }
    };
  } else {
    if (!fs.existsSync(absPath)) {
      console.error(`\x1b[31mError:\x1b[0m Target path does not exist: ${absPath}`);
      process.exit(1);
    }
    console.log(`\x1b[36m⚡ Scanning target:\x1b[0m ${absPath}`);
    results = scanDirectory(absPath, { entropy: !noEntropy });
  }

  // Print CLI report
  printCliReport(results);

  // Export HTML if requested
  if (htmlPath) {
    const fullHtmlPath = path.resolve(process.cwd(), htmlPath);
    writeHtmlReport(results, fullHtmlPath, path.basename(absPath));
    console.log(`\x1b[32m✓ HTML Security Report generated:\x1b[0m ${fullHtmlPath}\n`);
  }

  // Strict check / exit codes
  if (isStrict && results.summary.totalFindings > 0) {
    process.exit(1);
  } else if (results.summary.critical > 0) {
    process.exit(1);
  }

  process.exit(0);
}

main().catch(err => {
  console.error(`\x1b[31mUnexpected error:\x1b[0m`, err);
  process.exit(1);
});
