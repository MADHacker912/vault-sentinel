/**
 * VaultSentinel programmatic library entrypoint
 */

const { RULES } = require("./rules");
const { calculateShannonEntropy, scanHighEntropyTokens } = require("./entropy");
const { scanContent, scanDiff, scanDirectory, maskSecret } = require("./scanner");
const { isGitRepo, getStagedDiff, getCommitHistoryDiff, installPreCommitHook } = require("./git");
const { printBanner, printCliReport } = require("./reporter-cli");
const { generateHtmlReport, writeHtmlReport } = require("./reporter-html");

module.exports = {
  RULES,
  calculateShannonEntropy,
  scanHighEntropyTokens,
  scanContent,
  scanDiff,
  scanDirectory,
  maskSecret,
  isGitRepo,
  getStagedDiff,
  getCommitHistoryDiff,
  installPreCommitHook,
  printBanner,
  printCliReport,
  generateHtmlReport,
  writeHtmlReport
};
