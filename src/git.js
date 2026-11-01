/**
 * Git integration module
 * Handles git diffs, commits inspection, and pre-commit hook installation
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function isGitRepo(targetDir = process.cwd()) {
  try {
    execSync("git rev-parse --is-inside-work-tree", { cwd: targetDir, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function getStagedDiff(targetDir = process.cwd()) {
  try {
    return execSync("git diff --cached", { cwd: targetDir, maxBuffer: 10 * 1024 * 1024 }).toString("utf8");
  } catch (err) {
    return "";
  }
}

function getCommitHistoryDiff(depth = 20, targetDir = process.cwd()) {
  try {
    return execSync(`git log -p -n ${depth}`, { cwd: targetDir, maxBuffer: 25 * 1024 * 1024 }).toString("utf8");
  } catch (err) {
    return "";
  }
}

function installPreCommitHook(targetDir = process.cwd()) {
  const hooksDir = path.join(targetDir, ".git", "hooks");
  if (!fs.existsSync(hooksDir)) {
    throw new Error(`Target directory is not a git repository or has no .git/hooks directory: ${targetDir}`);
  }

  const hookPath = path.join(hooksDir, "pre-commit");
  const hookScript = `#!/usr/bin/env sh
# VaultSentinel Automated Pre-Commit Gate
echo "🛡️  Running VaultSentinel pre-commit secret scan..."

if command -v npx >/dev/null 2>&1; then
  npx vault-sentinel scan --staged
  EXIT_CODE=$?
else
  node ./bin/vault-sentinel.js scan --staged
  EXIT_CODE=$?
fi

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Commit aborted: Sensitive credentials detected by VaultSentinel!"
  echo "Fix the leaks or run with --no-verify if you are certain."
  exit 1
fi

exit 0
`;

  fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
  return hookPath;
}

module.exports = {
  isGitRepo,
  getStagedDiff,
  getCommitHistoryDiff,
  installPreCommitHook
};
