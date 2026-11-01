/**
 * Core scanning engine for VaultSentinel
 */

const fs = require("fs");
const path = require("path");
const { RULES } = require("./rules");
const { scanHighEntropyTokens } = require("./entropy");

const DEFAULT_IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  "vendor",
  ".cache",
  ".venv",
  "env"
]);

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
  ".mp4", ".mov", ".avi", ".mp3", ".wav",
  ".zip", ".tar", ".gz", ".7z", ".rar",
  ".pdf", ".docx", ".xlsx",
  ".exe", ".bin", ".so", ".dylib", ".dll",
  ".woff", ".woff2", ".ttf", ".eot",
  ".wasm", ".pyc", ".lock"
]);

function maskSecret(secret) {
  if (!secret) return "";
  if (secret.length <= 8) return "*".repeat(secret.length);
  const head = secret.slice(0, 4);
  const tail = secret.slice(-4);
  return `${head}${"*".repeat(Math.min(secret.length - 8, 16))}${tail}`;
}

function scanContent(content, filePath = "buffer", options = {}) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  const checkEntropy = options.entropy !== false;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    const lineNum = lineIdx + 1;

    // Skip excessively long lines (minified bundles)
    if (line.length > 2000) continue;

    // Check each rule
    for (const rule of RULES) {
      rule.regex.lastIndex = 0;
      let match;
      while ((match = rule.regex.exec(line)) !== null) {
        const secretVal = match[1] || match[0];
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          description: rule.description,
          file: filePath,
          line: lineNum,
          column: match.index + 1,
          masked: maskSecret(secretVal),
          snippet: line.trim()
        });
      }
    }

    // Shannon Entropy Check for unidentified secrets
    if (checkEntropy) {
      const entropyMatches = scanHighEntropyTokens(line);
      for (const ent of entropyMatches) {
        // avoid duplicate if already matched by structured rule
        const alreadyMatched = findings.some(f => f.file === filePath && f.line === lineNum && line.includes(ent.token));
        if (!alreadyMatched) {
          findings.push({
            ruleId: "ENTROPY-HIGH-099",
            ruleName: "High Shannon Entropy Token",
            severity: "MEDIUM",
            category: "Heuristic Anomaly",
            description: `Token exhibits abnormal entropy (${ent.entropy}), typical of encrypted hashes or generated keys.`,
            file: filePath,
            line: lineNum,
            column: line.indexOf(ent.token) + 1,
            masked: maskSecret(ent.token),
            snippet: line.trim()
          });
        }
      }
    }
  }

  return findings;
}

function scanDiff(diffContent, options = {}) {
  const findings = [];
  const lines = diffContent.split(/\r?\n/);
  let currentFile = "git-diff";

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];

    if (line.startsWith("diff --git")) {
      const parts = line.split(" ");
      if (parts.length >= 4) {
        currentFile = parts[3].replace(/^b\//, "");
      }
    }

    // Only scan newly added lines
    if (line.startsWith("+") && !line.startsWith("+++")) {
      const lineContent = line.slice(1);
      const lineFindings = scanContent(lineContent, currentFile, options);
      for (const f of lineFindings) {
        f.line = idx + 1; // approximate diff line
        findings.push(f);
      }
    }
  }

  return findings;
}

function scanDirectory(dirPath, options = {}) {
  const startTime = Date.now();
  const allFindings = [];
  let fileCount = 0;

  function traverse(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!DEFAULT_IGNORED_DIRS.has(entry.name)) {
          traverse(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;

        try {
          const stats = fs.statSync(fullPath);
          if (stats.size > 2 * 1024 * 1024) continue; // Skip files > 2MB

          const content = fs.readFileSync(fullPath, "utf8");
          fileCount++;
          const relPath = path.relative(dirPath, fullPath);
          const findings = scanContent(content, relPath, options);
          allFindings.push(...findings);
        } catch {
          // skip non-readable files
        }
      }
    }
  }

  traverse(dirPath);

  const durationMs = Date.now() - startTime;
  const summary = {
    totalFilesScanned: fileCount,
    totalFindings: allFindings.length,
    critical: allFindings.filter(f => f.severity === "CRITICAL").length,
    high: allFindings.filter(f => f.severity === "HIGH").length,
    medium: allFindings.filter(f => f.severity === "MEDIUM").length,
    low: allFindings.filter(f => f.severity === "LOW").length,
    durationMs
  };

  return { findings: allFindings, summary };
}

module.exports = {
  scanContent,
  scanDiff,
  scanDirectory,
  maskSecret
};
