// Standalone, dependency-free HTML report.
// Designed to be opened locally or shared as a GitHub Pages artifact.

const SEV_COLOR = {
  critical: '#b91c1c',
  high:     '#dc2626',
  medium:   '#d97706',
  low:      '#0891b2',
  info:     '#6b7280',
};

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityBadge(sev) {
  const color = SEV_COLOR[sev] || '#6b7280';
  return `<span class="badge" style="background:${color}">${escapeHtml(sev.toUpperCase())}</span>`;
}

function findingCard(f) {
  const evidenceRows = Object.entries(f.evidence || {})
    .map(([k, v]) => {
      const val = typeof v === 'string' ? v : JSON.stringify(v, null, 2);
      return `<div class="kv"><span class="k">${escapeHtml(k)}</span><pre class="v">${escapeHtml(val)}</pre></div>`;
    })
    .join('');
  const refs = (f.references || [])
    .map(r => `<li><a href="${escapeHtml(r)}" target="_blank" rel="noreferrer">${escapeHtml(r)}</a></li>`)
    .join('');
  return `
    <article class="finding sev-${f.severity}">
      <header>
        ${severityBadge(f.severity)}
        <h3>${escapeHtml(f.title)}</h3>
      </header>
      <div class="meta">rule: <code>${escapeHtml(f.ruleId)}</code> · target: <code>${escapeHtml(f.target.kind)}/${escapeHtml(f.target.name)}</code></div>
      <p>${escapeHtml(f.description)}</p>
      ${evidenceRows ? `<details open><summary>Evidence</summary>${evidenceRows}</details>` : ''}
      ${f.remediation ? `<div class="remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
      ${refs ? `<details><summary>References</summary><ul>${refs}</ul></details>` : ''}
    </article>
  `;
}

export function renderHtml(report) {
  const { server, summary, findings, auditedAt } = report;

  const summaryRow = ['critical', 'high', 'medium', 'low', 'info']
    .map(sev => {
      const n = summary.bySeverity[sev] || 0;
      return `<div class="sev-tile" style="border-color:${SEV_COLOR[sev]}"><span class="n">${n}</span><span class="l">${sev}</span></div>`;
    })
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>MCP Audit · ${escapeHtml(server.name)}</title>
  <style>
    :root {
      --bg:#0b0f17; --panel:#111827; --border:#1f2937; --text:#e5e7eb; --dim:#94a3b8; --accent:#22d3ee;
    }
    * { box-sizing:border-box; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
           background:var(--bg); color:var(--text); line-height:1.5; }
    .wrap { max-width:960px; margin:0 auto; padding:32px 24px 64px; }
    h1 { margin:0 0 8px; font-size:28px; }
    h2 { margin:32px 0 12px; font-size:18px; color:var(--accent); letter-spacing:0.05em; text-transform:uppercase; }
    h3 { margin:0; font-size:16px; }
    .server { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px 20px; margin-top:16px; }
    .server .row { display:flex; gap:24px; flex-wrap:wrap; font-size:13px; color:var(--dim); }
    .server .row b { color:var(--text); font-weight:600; margin-right:6px; }
    .summary { display:flex; gap:10px; flex-wrap:wrap; margin-top:8px; }
    .sev-tile { background:var(--panel); border:2px solid var(--border); border-radius:8px;
                padding:10px 14px; min-width:90px; display:flex; flex-direction:column; align-items:center; }
    .sev-tile .n { font-size:24px; font-weight:700; }
    .sev-tile .l { font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:var(--dim); }
    .finding { background:var(--panel); border:1px solid var(--border); border-left-width:4px;
               border-radius:8px; padding:16px 18px; margin:12px 0; }
    .finding.sev-critical { border-left-color:${SEV_COLOR.critical}; }
    .finding.sev-high     { border-left-color:${SEV_COLOR.high}; }
    .finding.sev-medium   { border-left-color:${SEV_COLOR.medium}; }
    .finding.sev-low      { border-left-color:${SEV_COLOR.low}; }
    .finding.sev-info     { border-left-color:${SEV_COLOR.info}; }
    .finding header { display:flex; align-items:center; gap:10px; margin-bottom:8px; }
    .badge { font-size:10px; font-weight:700; letter-spacing:0.06em; padding:2px 8px; border-radius:999px; color:#fff; }
    .meta { font-size:12px; color:var(--dim); margin-bottom:8px; }
    code { background:#1f2937; padding:1px 6px; border-radius:4px; font-size:12px; }
    pre { background:#0a0e16; border:1px solid var(--border); border-radius:6px; padding:8px 10px;
          overflow:auto; font-size:12px; color:#cbd5e1; white-space:pre-wrap; word-break:break-word; }
    .kv { margin:6px 0; }
    .kv .k { display:inline-block; font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:0.06em; margin-right:6px; }
    .kv .v { margin:4px 0 0; }
    .remediation { background:#0a0e16; border:1px solid var(--border); border-radius:6px;
                   padding:8px 10px; font-size:13px; margin-top:8px; }
    details summary { cursor:pointer; font-size:12px; color:var(--dim); margin:8px 0 4px; }
    .footer { margin-top:32px; font-size:12px; color:var(--dim); text-align:center; }
    .empty { background:var(--panel); border:1px solid var(--border); border-radius:8px;
             padding:32px; text-align:center; color:var(--dim); }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>MCP Audit Report</h1>
    <div class="server">
      <div class="row"><div><b>Server</b>${escapeHtml(server.name)}${server.version ? ' v' + escapeHtml(server.version) : ''}</div></div>
      <div class="row">
        <div><b>Transport</b>${escapeHtml(server.transport)}</div>
        ${server.url ? `<div><b>URL</b>${escapeHtml(server.url)}</div>` : ''}
        ${server.auth ? `<div><b>Auth</b>${escapeHtml(server.auth.kind)}${server.auth.required ? ' (required)' : ''}</div>` : ''}
      </div>
      <div class="row">
        <div><b>Tools</b>${server.counts.tools}</div>
        <div><b>Resources</b>${server.counts.resources}</div>
        <div><b>Prompts</b>${server.counts.prompts}</div>
      </div>
    </div>

    <h2>Summary</h2>
    <div class="summary">${summaryRow}</div>

    <h2>Findings (${findings.length})</h2>
    ${findings.length === 0
      ? `<div class="empty">No findings. Server passed all rules.</div>`
      : findings.map(findingCard).join('')}

    <div class="footer">audited at ${escapeHtml(auditedAt)} · mcp-audit</div>
  </div>
</body>
</html>`;
}
