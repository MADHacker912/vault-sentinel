/**
 * CLI Terminal Report Formatter
 * Pure ANSI formatting with zero external dependencies
 */

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m"
};

function printBanner() {
  const banner = `
${ANSI.cyan}${ANSI.bold}╦  ╦╔═╗╦ ╦╦  ╔╦╗  ╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦  
╚╗╔╝╠═╣║ ║║   ║   ╚═╗║╣ ║║║ ║ ║║║║║╣ ║  
 ╚╝ ╩ ╩╚═╝╩═╝ ╩   ╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝${ANSI.reset}
${ANSI.dim}⚡ High-Precision Secret Leak & Entropy Scanner for Git Repositories${ANSI.reset}
`;
  console.log(banner);
}

function getSeverityBadge(severity) {
  switch (severity) {
    case "CRITICAL":
      return `${ANSI.bgRed}${ANSI.white}${ANSI.bold} CRITICAL ${ANSI.reset}`;
    case "HIGH":
      return `${ANSI.red}${ANSI.bold}[HIGH]${ANSI.reset}`;
    case "MEDIUM":
      return `${ANSI.yellow}${ANSI.bold}[MEDIUM]${ANSI.reset}`;
    case "LOW":
      return `${ANSI.blue}${ANSI.bold}[LOW]${ANSI.reset}`;
    default:
      return `[${severity}]`;
  }
}

function printCliReport(results) {
  const { findings, summary } = results;

  if (findings.length === 0) {
    console.log(`\n${ANSI.green}${ANSI.bold}✓ Clean Scan:${ANSI.reset} ${ANSI.white}No credential leaks or high-entropy anomalies detected!${ANSI.reset}`);
    console.log(`${ANSI.dim}Scanned ${summary.totalFilesScanned || 0} files in ${summary.durationMs || 0}ms${ANSI.reset}\n`);
    return;
  }

  console.log(`\n${ANSI.red}${ANSI.bold}⚠ Security Vulnerabilities Detected (${findings.length} findings):${ANSI.reset}\n`);

  findings.forEach((finding, index) => {
    console.log(`${ANSI.dim}#${index + 1}${ANSI.reset} ${getSeverityBadge(finding.severity)} ${ANSI.bold}${finding.ruleName}${ANSI.reset} ${ANSI.dim}(${finding.ruleId})${ANSI.reset}`);
    console.log(`   ${ANSI.cyan}Location:${ANSI.reset} ${finding.file}:${finding.line}:${finding.column}`);
    console.log(`   ${ANSI.magenta}Category:${ANSI.reset} ${finding.category}`);
    console.log(`   ${ANSI.yellow}Masked:${ANSI.reset}   ${finding.masked}`);
    if (finding.snippet) {
      console.log(`   ${ANSI.dim}Code:${ANSI.reset}     ${finding.snippet}`);
    }
    console.log("");
  });

  // Summary Table
  console.log(`${ANSI.bold}┌──────────────────────────────────────────┐${ANSI.reset}`);
  console.log(`${ANSI.bold}│          SCAN AUDIT SUMMARY              │${ANSI.reset}`);
  console.log(`${ANSI.bold}├──────────────────────────────────────────┤${ANSI.reset}`);
  console.log(`│ Total Files Scanned: ${String(summary.totalFilesScanned).padEnd(20)}│`);
  console.log(`│ Total Leaks Found:   ${String(summary.totalFindings).padEnd(20)}│`);
  console.log(`│   ${ANSI.red}Critical:${ANSI.reset}          ${String(summary.critical).padEnd(20)}│`);
  console.log(`│   ${ANSI.yellow}High:${ANSI.reset}              ${String(summary.high).padEnd(20)}│`);
  console.log(`│   ${ANSI.blue}Medium:${ANSI.reset}            ${String(summary.medium).padEnd(20)}│`);
  console.log(`│   ${ANSI.dim}Low:${ANSI.reset}               ${String(summary.low).padEnd(20)}│`);
  console.log(`│ Scan Duration:       ${(summary.durationMs + " ms").padEnd(20)}│`);
  console.log(`${ANSI.bold}└──────────────────────────────────────────┘${ANSI.reset}\n`);
}

module.exports = {
  printBanner,
  printCliReport,
  ANSI
};
