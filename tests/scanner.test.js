/**
 * Unit Test Suite for VaultSentinel
 */

const assert = require("assert");
const { scanContent, maskSecret } = require("../src/scanner");
const { calculateShannonEntropy } = require("../src/entropy");
const { RULES } = require("../src/rules");

console.log("🧪 Running VaultSentinel Test Suite...\n");

let passed = 0;
let total = 0;

function it(name, fn) {
  total++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
  }
}

// Test 1: Masking
it("Should correctly mask sensitive strings", () => {
  assert.strictEqual(maskSecret("short"), "*****");
  const maskedLong = maskSecret(["sk", "proj", "1234567890abcdef12345678"].join("-"));
  assert(maskedLong.startsWith("sk-p"));
  assert(maskedLong.endsWith("5678"));
  assert(maskedLong.includes("*"));
});

// Test 2: Shannon Entropy
it("Should compute higher entropy for random strings than repetitive ones", () => {
  const lowEntropy = calculateShannonEntropy("aaaaaaaaaaaaaaaa");
  const highEntropy = calculateShannonEntropy("pX9$mK2#vL8@qZ4!wY7%jB1&");
  assert(lowEntropy < 1.0);
  assert(highEntropy > 3.8);
});

// Test 3: AWS Key Detection
it("Should detect exposed AWS access key ID", () => {
  const dummyAws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const sample = `const awsKey = '${dummyAws}';`;
  const findings = scanContent(sample, "aws.js", { entropy: false });
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, "AWS-KEY-001");
  assert.strictEqual(findings[0].severity, "CRITICAL");
});

// Test 4: OpenAI API Key Detection
it("Should detect standard OpenAI API key", () => {
  const dummyOpenAI = ["sk", "proj", "abcdefghijklmnopqrstuvwxyz1234567890"].join("-");
  const sample = `export OPENAI_API_KEY=${dummyOpenAI}`;
  const findings = scanContent(sample, ".env", { entropy: false });
  assert(findings.some(f => f.ruleId === "OPENAI-KEY-005"));
});

// Test 5: GitHub PAT
it("Should detect GitHub Personal Access Token", () => {
  const dummyGhp = ["ghp", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"].join("_");
  const sample = `token = '${dummyGhp}'`;
  const findings = scanContent(sample, "config.json", { entropy: false });
  assert(findings.some(f => f.ruleId === "GITHUB-PAT-008"));
});

// Test 6: Database Connection String
it("Should detect database connection string with password", () => {
  const dummyDb = ["postgres:", "/admin:superSecret123@db.prod.internal:5432/main"].join("/");
  const sample = `DATABASE_URL=${dummyDb}`;
  const findings = scanContent(sample, "db.js", { entropy: false });
  assert(findings.some(f => f.ruleId === "DB-CONN-020"));
});

// Test 7: Stripe Live Key
it("Should detect Stripe live secret key", () => {
  const dummyStripe = ["sk", "live", "51AbcdefghijklmnoPqrstuvwxyz12345"].join("_");
  const sample = `stripe_secret = '${dummyStripe}'`;
  const findings = scanContent(sample, "billing.py", { entropy: false });
  assert(findings.some(f => f.ruleId === "STRIPE-KEY-011"));
});

// Test 8: Clean Code Safety
it("Should not produce false positives on standard clean code", () => {
  const cleanCode = `
    function add(a, b) {
      const sum = a + b;
      return sum;
    }
    const publicUrl = "https://example.com/api/v1/users";
  `;
  const findings = scanContent(cleanCode, "app.js", { entropy: false });
  assert.strictEqual(findings.length, 0);
});

console.log(`\nResults: ${passed}/${total} tests passed.`);
if (passed !== total) {
  process.exit(1);
}
