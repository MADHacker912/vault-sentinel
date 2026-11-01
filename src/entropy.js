/**
 * Shannon Entropy calculation for detecting randomized, obfuscated secrets
 */

function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;

  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Scan a line for high-entropy tokens (potential unclassified secrets)
 */
function scanHighEntropyTokens(line, threshold = 4.3, minLength = 24) {
  const matches = [];
  // Tokenize line by whitespace, quotes, commas, equals
  const tokens = line.split(/[\s"',;:=(){}\[\]<>]+/);

  for (const rawToken of tokens) {
    const token = rawToken.replace(/^\/+/, "");
    // Skip common code artifacts, paths, URLs, long words without variety
    if (token.length < minLength || token.length > 120) continue;
    if (token.startsWith("http") || token.includes("://") || token.includes(".com") || token.includes(".org") || token.includes(".io") || token.includes(".net") || token.includes("/")) continue;
    if (/^[0-9]+$/.test(token)) continue; // numbers only
    if (/^[a-zA-Z]+$/.test(token) && !/[A-Z]/.test(token.slice(1))) continue; // plain lowercase words
    if (token.includes("%") || token.includes("&") && token.includes("=")) continue; // URL encoded strings

    const entropy = calculateShannonEntropy(token);
    if (entropy >= threshold) {
      matches.push({
        token,
        entropy: parseFloat(entropy.toFixed(2))
      });
    }
  }

  return matches;
}

module.exports = {
  calculateShannonEntropy,
  scanHighEntropyTokens
};
