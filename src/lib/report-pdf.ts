import type { ScanReport } from "./types.ts";

// A A4 layout rendered to PDF by headless Chromium. All report-derived strings
// are escaped, they carry site-controlled text (URLs, titles, field names).

export function escapeHtml(text: string): string {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

const SEVERITY_COLORS: Record<string, string> = {
    High: "#b91c1c",
    Medium: "#b45309",
    Low: "#0369a1",
};

const GRADE_COLORS: Record<string, string> = {
    A: "#15803d",
    B: "#4d7c0f",
    C: "#b45309",
    D: "#c2410c",
    F: "#b91c1c",
};

function chip(text: string, color: string): string {
    return `<span class="chip" style="color:${color};border-color:${color}">${escapeHtml(text)}</span>`;
}

export function buildReportHtml(report: ScanReport): string {
    const gradeColor = GRADE_COLORS[report.grade] ?? "#374151";
    const findings = report.findings.length
        ? report.findings
              .map(
                  (f) => `
      <div class="finding">
        <div class="finding-head">
          ${chip(f.severity, SEVERITY_COLORS[f.severity] ?? "#374151")}
          <span class="confidence">${escapeHtml(f.confidence === "verified" ? "Direct evidence" : f.confidence === "inferred" ? "Inferred" : "Could not verify")}</span>
          <span class="category">${escapeHtml(f.category)}</span>
        </div>
        <div class="finding-title">${escapeHtml(f.title)}</div>
        <p><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</p>
        <p><strong>Why it matters:</strong> ${escapeHtml(f.hipaaRisk)}</p>
        <p><strong>Fix:</strong> ${escapeHtml(f.recommendation)}</p>
      </div>`
              )
              .join("")
        : `<p class="muted">No findings recorded for this scan.</p>`;

    const domains = report.thirdPartyDomains.length
        ? `<table>
      <thead><tr><th>Domain</th><th>Category</th><th>Requests</th></tr></thead>
      <tbody>
        ${report.thirdPartyDomains
            .map(
                (d) =>
                    `<tr><td>${escapeHtml(d.domain)}</td><td>${escapeHtml(d.category)}</td><td>${d.requestCount}</td></tr>`
            )
            .join("")}
      </tbody>
    </table>`
        : `<p class="muted">No third-party domains observed.</p>`;

    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Website Checker report: ${escapeHtml(report.targetUrl)}</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: Helvetica, Arial, sans-serif;
    color: #1f2937;
    font-size: 10.5pt;
    line-height: 1.45;
    margin: 0;
  }
  .header {
    border-bottom: 3px solid #c2410c;
    padding-bottom: 14pt;
    margin-bottom: 14pt;
  }
  h1 { font-size: 17pt; margin: 0 0 4pt; color: #111827; }
  .meta { color: #6b7280; font-size: 9pt; word-break: break-all; }
  .scorecard { display: flex; align-items: center; gap: 12pt; margin: 14pt 0; }
  .grade {
    width: 42pt; height: 42pt; border-radius: 50%;
    border: 3pt solid ${gradeColor};
    color: ${gradeColor};
    font-size: 20pt; font-weight: bold;
    display: flex; align-items: center; justify-content: center;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .scorecard .risk { font-size: 13pt; font-weight: bold; }
  .scorecard .counts { color: #6b7280; font-size: 9.5pt; }
  .summary { margin: 12pt 0; font-size: 10.5pt; }
  h2 { font-size: 12pt; margin: 16pt 0 8pt; color: #111827; }
  .finding {
    border: 0.75pt solid #d1d5db;
    border-radius: 6pt;
    padding: 9pt 11pt;
    margin-bottom: 9pt;
    break-inside: avoid;
  }
  .finding-head { display: flex; gap: 8pt; align-items: baseline; margin-bottom: 4pt; }
  .chip {
    border: 1pt solid; border-radius: 8pt;
    padding: 0.5pt 7pt; font-size: 8.5pt; font-weight: bold;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  .confidence { font-size: 8.5pt; font-weight: bold; color: #6b7280; }
  .category { font-size: 8.5pt; color: #9ca3af; margin-left: auto; }
  .finding-title { font-weight: bold; font-size: 11pt; margin-bottom: 4pt; }
  p { margin: 3pt 0; }
  table { width: 100%; border-collapse: collapse; font-size: 9.5pt; }
  th, td { border-bottom: 0.5pt solid #e5e7eb; padding: 4pt 6pt; text-align: left; word-break: break-all; }
  th { color: #6b7280; font-weight: bold; font-size: 8.5pt; text-transform: uppercase; }
  .muted { color: #6b7280; }
  .footer {
    margin-top: 20pt; padding-top: 10pt;
    border-top: 0.75pt solid #d1d5db;
    color: #6b7280; font-size: 8.5pt;
  }
</style>
</head>
<body>
  <div class="header">
    <h1>HIPAA and PHI privacy report</h1>
    <div class="meta">${escapeHtml(report.targetUrl)} &middot; scanned ${escapeHtml(new Date(report.scannedAt).toLocaleString())}</div>
  </div>

  <div class="scorecard">
    <div class="grade">${escapeHtml(report.grade)}</div>
    <div>
      <div class="risk">${escapeHtml(report.riskLevel)} risk</div>
      <div class="counts">${report.findings.filter((f) => f.severity === "High").length} high &middot; ${report.findings.filter((f) => f.severity === "Medium").length} medium &middot; ${report.findings.filter((f) => f.severity === "Low").length} low findings</div>
    </div>
  </div>

  <p class="summary">${escapeHtml(report.summary)}</p>

  <h2>Findings</h2>
  ${findings}

  <h2>Third-party domains observed</h2>
  ${domains}

  <div class="footer">
    Automated technical review only. Not legal advice or a HIPAA compliance certification.
    Generated by Website Checker on ${escapeHtml(new Date().toLocaleString())}.
  </div>
</body>
</html>`;
}
