/**
 * VaultSentinel - Rule Engine Definitions
 * High-fidelity regular expressions for credential and secret detection
 */

const RULES = [
  // Cloud Providers
  {
    id: "AWS-KEY-001",
    name: "AWS Access Key ID",
    severity: "CRITICAL",
    category: "Cloud Credentials",
    regex: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
    description: "Identifies standard AWS IAM and STS credentials."
  },
  {
    id: "AWS-SEC-002",
    name: "AWS Secret Access Key",
    severity: "CRITICAL",
    category: "Cloud Credentials",
    regex: /(?:aws_secret_access_key|aws_sec_key|aws_secret|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    description: "Detects paired AWS Secret Keys exposed in configuration."
  },
  {
    id: "GCP-KEY-003",
    name: "Google Cloud Platform API Key",
    severity: "HIGH",
    category: "Cloud Credentials",
    regex: /\b(AIza[0-9A-Za-z-_]{35})\b/g,
    description: "Matches public or private GCP API keys."
  },
  {
    id: "GCP-OAUTH-004",
    name: "GCP OAuth Secret",
    severity: "CRITICAL",
    category: "Cloud Credentials",
    regex: /(?:client_secret|clientSecret)\s*[:=]\s*["']?([a-zA-Z0-9-_]{24,35})["']?/g,
    description: "Identifies Google OAuth client secret definitions."
  },

  // AI & LLM Providers
  {
    id: "OPENAI-KEY-005",
    name: "OpenAI API Key",
    severity: "CRITICAL",
    category: "AI & ML",
    regex: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{32,128})\b/g,
    description: "Finds OpenAI standard and project-scoped API tokens."
  },
  {
    id: "ANTHROPIC-KEY-006",
    name: "Anthropic Claude API Key",
    severity: "CRITICAL",
    category: "AI & ML",
    regex: /\b(sk-ant-[a-zA-Z0-9_-]{40,128})\b/g,
    description: "Matches Anthropic Claude commercial API keys."
  },
  {
    id: "HUGGINGFACE-KEY-007",
    name: "HuggingFace Access Token",
    severity: "HIGH",
    category: "AI & ML",
    regex: /\b(hf_[a-zA-Z0-9]{34,60})\b/g,
    description: "Matches HuggingFace read/write access tokens."
  },

  // Code Hosts & VCS
  {
    id: "GITHUB-PAT-008",
    name: "GitHub Personal Access Token",
    severity: "CRITICAL",
    category: "Version Control",
    regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\b/g,
    description: "Matches legacy and classic GitHub Personal Access Tokens."
  },
  {
    id: "GITHUB-FINE-009",
    name: "GitHub Fine-Grained Token",
    severity: "CRITICAL",
    category: "Version Control",
    regex: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
    description: "Matches fine-grained GitHub user tokens."
  },
  {
    id: "GITLAB-PAT-010",
    name: "GitLab Personal Access Token",
    severity: "CRITICAL",
    category: "Version Control",
    regex: /\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,
    description: "Matches GitLab developer and project tokens."
  },

  // Payment Processors
  {
    id: "STRIPE-KEY-011",
    name: "Stripe Live Secret Key",
    severity: "CRITICAL",
    category: "Payments",
    regex: /\b(sk_live_[0-9a-zA-Z]{24,99})\b/g,
    description: "Exposed live secret key capable of transaction manipulation."
  },
  {
    id: "STRIPE-RESTRICTED-012",
    name: "Stripe Restricted Key",
    severity: "HIGH",
    category: "Payments",
    regex: /\b(rk_live_[0-9a-zA-Z]{24,99})\b/g,
    description: "Matches restricted operational Stripe keys."
  },

  // Communications & Messaging
  {
    id: "SLACK-TOKEN-013",
    name: "Slack Bot / User Token",
    severity: "HIGH",
    category: "Messaging",
    regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34})\b/g,
    description: "Slack API bot or user OAuth credentials."
  },
  {
    id: "SLACK-WEBHOOK-014",
    name: "Slack Incoming Webhook",
    severity: "MEDIUM",
    category: "Messaging",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g,
    description: "Exposed incoming webhook allowing unauthorized channel messaging."
  },
  {
    id: "DISCORD-BOT-015",
    name: "Discord Bot Token",
    severity: "CRITICAL",
    category: "Messaging",
    regex: /\b([MN][A-Za-z\d]{23,26}\.[\w-]{6}\.[\w-]{27,38})\b/g,
    description: "Discord Bot Authentication Token."
  },
  {
    id: "TELEGRAM-BOT-016",
    name: "Telegram Bot Token",
    severity: "HIGH",
    category: "Messaging",
    regex: /\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,
    description: "Telegram Bot API authentication token."
  },
  {
    id: "TWILIO-KEY-017",
    name: "Twilio Account SID & Token",
    severity: "HIGH",
    category: "Messaging",
    regex: /\b(AC[a-z0-9]{32})\b/gi,
    description: "Twilio Account identification token."
  },

  // Cryptographic Keys
  {
    id: "PRIVKEY-RSA-018",
    name: "RSA / SSH Private Key",
    severity: "CRITICAL",
    category: "Cryptography",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{30,2000}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    description: "Unencrypted cryptographic private key exposed in plaintext."
  },
  {
    id: "PRIVKEY-PGP-019",
    name: "PGP Private Key Block",
    severity: "CRITICAL",
    category: "Cryptography",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{30,2000}?-----END PGP PRIVATE KEY BLOCK-----/g,
    description: "PGP private armor key block."
  },

  // Databases & Backend Infrastructure
  {
    id: "DB-CONN-020",
    name: "Database Connection String (URI)",
    severity: "CRITICAL",
    category: "Databases",
    regex: /\b(?:postgres|postgresql|mongodb|mongodb\+srv|mysql|redis):\/\/[^:\s'"]+:[^@\s'"]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_.-]+/gi,
    description: "Database connection string containing embedded cleartext credentials."
  },
  {
    id: "JWT-TOKEN-021",
    name: "JSON Web Token (JWT)",
    severity: "MEDIUM",
    category: "Authentication",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    description: "Bearer or session JWT token containing signed claims or access roles."
  },

  // Package Managers & Dev Ecosystem
  {
    id: "NPM-TOKEN-022",
    name: "NPM Access Token",
    severity: "CRITICAL",
    category: "Package Registry",
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
    description: "NPM registry automation or publish token."
  },
  {
    id: "PYPI-TOKEN-023",
    name: "PyPI Upload Token",
    severity: "CRITICAL",
    category: "Package Registry",
    regex: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,150})\b/g,
    description: "PyPI package upload and distribution token."
  },
  {
    id: "SENDGRID-KEY-024",
    name: "SendGrid API Key",
    severity: "HIGH",
    category: "Email Services",
    regex: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/g,
    description: "SendGrid transactional email API key."
  },

  // Generic High-Entropy & Key Patterns
  {
    id: "GENERIC-SECRET-025",
    name: "Generic API Secret / Password Assignment",
    severity: "MEDIUM",
    category: "Generic Secrets",
    regex: /(?:secret|password|passwd|api_key|apikey|auth_token|access_token|private_key)\s*[:=]\s*["']([a-zA-Z0-9!@#$%^&*()_+=-]{16,64})["']/gi,
    description: "Variable assignment with high-confidence secret naming convention."
  }
];

module.exports = { RULES };
