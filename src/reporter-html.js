/**
 * HTML Security Dashboard Generator
 * Produces a high-aesthetic, standalone, offline dark-glass audit report
 */

const fs = require("fs");
const path = require("path");

function generateHtmlReport(results, targetDir = "Repository") {
  const { findings, summary } = results;
  const timestamp = new Date().toUTCString();
  const safeData = JSON.stringify(findings).replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VaultSentinel Security Audit Report</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.7);
      --border: rgba(255, 255, 255, 0.08);
      --border-glow: rgba(0, 242, 254, 0.25);
      --text-main: #f0f4f8;
      --text-muted: #94a3b8;
      --accent: #00f2fe;
      --accent-alt: #4facfe;
      --critical: #ff3366;
      --high: #ff9900;
      --medium: #facc15;
      --low: #38bdf8;
      --clean: #10b981;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 10% 10%, #0d1527 0%, var(--bg) 100%);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      min-height: 100vh;
      padding: 2.5rem 1.5rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .logo-group h1 {
      font-size: 1.85rem;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, var(--accent) 0%, #a855f7 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .logo-group p {
      color: var(--text-muted);
      font-size: 0.88rem;
      margin-top: 0.25rem;
    }

    .meta-badge {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      padding: 0.5rem 1rem;
      border-radius: 999px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    /* Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }

    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.25rem 1.5rem;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      border-color: var(--border-glow);
    }
    .metric-title {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }
    .metric-value {
      font-size: 2.2rem;
      font-weight: 800;
      margin-top: 0.35rem;
      color: #fff;
    }
    .val-critical { color: var(--critical); }
    .val-high { color: var(--high); }
    .val-clean { color: var(--clean); }

    /* Controls Bar */
    .controls-bar {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }
    .search-input {
      flex: 1;
      min-width: 260px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.75rem 1rem;
      color: #fff;
      font-size: 0.9rem;
      outline: none;
      transition: border-color 0.2s;
    }
    .search-input:focus {
      border-color: var(--accent);
    }
    .filter-tags {
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }
    .filter-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.5rem 0.9rem;
      border-radius: 8px;
      font-size: 0.8rem;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }
    .filter-btn.active, .filter-btn:hover {
      background: rgba(0, 242, 254, 0.15);
      border-color: var(--accent);
      color: #fff;
    }

    /* Findings List */
    .findings-container {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem 1.5rem;
      backdrop-filter: blur(8px);
      transition: all 0.2s ease;
    }
    .finding-card:hover {
      border-color: rgba(255, 255, 255, 0.2);
    }
    .card-top {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 0.75rem;
    }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .badge-CRITICAL { background: rgba(255, 51, 102, 0.15); color: var(--critical); border: 1px solid rgba(255, 51, 102, 0.4); }
    .badge-HIGH { background: rgba(255, 153, 0, 0.15); color: var(--high); border: 1px solid rgba(255, 153, 0, 0.4); }
    .badge-MEDIUM { background: rgba(250, 204, 21, 0.15); color: var(--medium); border: 1px solid rgba(250, 204, 21, 0.4); }
    .badge-LOW { background: rgba(56, 189, 248, 0.15); color: var(--low); border: 1px solid rgba(56, 189, 248, 0.4); }

    .rule-title {
      font-size: 1.05rem;
      font-weight: 700;
      margin-right: 0.75rem;
    }
    .rule-id {
      color: var(--text-muted);
      font-size: 0.78rem;
      font-family: monospace;
    }
    .file-loc {
      color: var(--accent);
      font-family: monospace;
      font-size: 0.85rem;
      margin-bottom: 0.5rem;
    }
    .desc-text {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-bottom: 0.75rem;
    }
    .code-box {
      background: rgba(0, 0, 0, 0.5);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.82rem;
      color: #38bdf8;
      overflow-x: auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .masked-val {
      color: #ff3366;
      font-weight: bold;
    }

    .clean-state {
      text-align: center;
      padding: 4rem 2rem;
      background: var(--card-bg);
      border-radius: 16px;
      border: 1px solid var(--border);
    }
    .clean-state h2 {
      color: var(--clean);
      font-size: 1.8rem;
      margin-bottom: 0.5rem;
    }

    footer {
      margin-top: 3.5rem;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.8rem;
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-group">
        <h1>🛡️ VaultSentinel</h1>
        <p>Target: <strong>${targetDir}</strong> &bull; Generated: ${timestamp}</p>
      </div>
      <div class="meta-badge">
        Audit Version: 1.0.0
      </div>
    </header>

    <section class="metrics-grid">
      <div class="metric-card">
        <div class="metric-title">Scanned Files</div>
        <div class="metric-value">${summary.totalFilesScanned || 0}</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Total Leaks</div>
        <div class="metric-value ${summary.totalFindings > 0 ? "val-critical" : "val-clean"}">${summary.totalFindings}</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Critical Leaks</div>
        <div class="metric-value val-critical">${summary.critical}</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">High Risk</div>
        <div class="metric-value val-high">${summary.high}</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Scan Duration</div>
        <div class="metric-value" style="font-size: 1.8rem;">${summary.durationMs || 0}<span style="font-size: 1rem; color: var(--text-muted);">ms</span></div>
      </div>
    </section>

    ${summary.totalFindings > 0 ? `
    <div class="controls-bar">
      <input type="text" id="searchBox" class="search-input" placeholder="Filter by rule, file name, or category...">
      <div class="filter-tags">
        <button class="filter-btn active" data-filter="ALL">All (${summary.totalFindings})</button>
        <button class="filter-btn" data-filter="CRITICAL">Critical (${summary.critical})</button>
        <button class="filter-btn" data-filter="HIGH">High (${summary.high})</button>
        <button class="filter-btn" data-filter="MEDIUM">Medium (${summary.medium})</button>
      </div>
    </div>

    <div class="findings-container" id="findingsContainer"></div>
    ` : `
    <div class="clean-state">
      <h2>✓ Repository Secure</h2>
      <p style="color: var(--text-muted); margin-top: 0.5rem;">No exposed credentials, private keys, or abnormal Shannon entropy tokens found in this scan.</p>
    </div>
    `}

    <footer>
      Protected by <strong>VaultSentinel</strong> &bull; Crafted by <a href="https://github.com/MADHacker912" style="color: var(--accent); text-decoration: none;">MADHacker912</a>
    </footer>
  </div>

  <script>
    const findings = ${safeData};
    const container = document.getElementById("findingsContainer");
    const searchInput = document.getElementById("searchBox");
    const filterBtns = document.querySelectorAll(".filter-btn");

    let currentFilter = "ALL";
    let searchQuery = "";

    function render() {
      if (!container) return;
      container.innerHTML = "";

      const filtered = findings.filter(f => {
        const matchesFilter = (currentFilter === "ALL") || (f.severity === currentFilter);
        const matchesSearch = !searchQuery || 
          f.ruleName.toLowerCase().includes(searchQuery) ||
          f.file.toLowerCase().includes(searchQuery) ||
          f.category.toLowerCase().includes(searchQuery);
        return matchesFilter && matchesSearch;
      });

      if (filtered.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding: 2rem; color: var(--text-muted);">No findings match your active filter.</div>';
        return;
      }

      filtered.forEach(item => {
        const card = document.createElement("div");
        card.className = "finding-card";
        card.innerHTML = \`
          <div class="card-top">
            <div>
              <span class="rule-title">\${item.ruleName}</span>
              <span class="rule-id">[\${item.ruleId}]</span>
            </div>
            <span class="badge badge-\${item.severity}">\${item.severity}</span>
          </div>
          <div class="file-loc">📍 \${item.file}:\${item.line}:\${item.column} &bull; <span style="color:var(--text-muted)">\${item.category}</span></div>
          <div class="desc-text">\${item.description}</div>
          <div class="code-box">
            <span><code>\${escapeHtml(item.snippet || item.masked)}</code></span>
            <span class="masked-val">\${escapeHtml(item.masked)}</span>
          </div>
        \`;
        container.appendChild(card);
      });
    }

    function escapeHtml(str) {
      if (!str) return "";
      return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        searchQuery = e.target.value.toLowerCase().trim();
        render();
      });
    }

    filterBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        filterBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        currentFilter = btn.dataset.filter;
        render();
      });
    });

    render();
  </script>
</body>
</html>`;
}

function writeHtmlReport(results, outputPath, targetDir) {
  const html = generateHtmlReport(results, targetDir);
  fs.writeFileSync(outputPath, html, "utf8");
  return outputPath;
}

module.exports = {
  generateHtmlReport,
  writeHtmlReport
};
