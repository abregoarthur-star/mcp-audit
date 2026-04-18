// Terminal reporter for `mcp-audit diff`.
import kleur from 'kleur';

const SEV_COLOR = {
  critical: kleur.bgRed().white().bold,
  high:     kleur.red().bold,
  medium:   kleur.yellow,
  low:      kleur.gray,
};

function badge(severity) {
  const color = SEV_COLOR[severity] || kleur.white;
  return color(` ${severity.toUpperCase().padEnd(8)} `);
}

export function renderDiffTerminal(result) {
  const lines = [];
  lines.push('');
  lines.push(kleur.bold('MCP Audit Diff'));
  lines.push(`Baseline:  ${result.baseline.name}  (${result.baseline.tools} tools, caps: ${result.baseline.caps.join(', ') || '—'})`);
  lines.push(`Current:   ${result.current.name}   (${result.current.tools} tools, caps: ${result.current.caps.join(', ') || '—'})`);
  lines.push(`Changes:   ${result.changes.added} added · ${result.changes.removed} removed · ${result.changes.changed} changed`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(kleur.green('  No changes detected. Surfaces are identical.'));
    lines.push('');
    return lines.join('\n');
  }

  const { bySeverity } = result.summary;
  lines.push(kleur.bold('Summary'));
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const n = bySeverity[sev] || 0;
    if (n > 0) lines.push(`  ${sev.padEnd(9)} ${n}`);
  }
  lines.push('');

  lines.push(kleur.bold(`Findings (${result.findings.length})`));
  lines.push('─'.repeat(70));

  const sortOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...result.findings].sort((a, b) => (sortOrder[a.severity] ?? 9) - (sortOrder[b.severity] ?? 9));

  for (const f of sorted) {
    lines.push(`${badge(f.severity)} ${f.title}`);
    lines.push(`  rule: ${f.ruleId}${f.target?.name ? `  ·  target: ${f.target.kind}/${f.target.name}` : ''}`);
    if (f.evidence && Object.keys(f.evidence).length > 0) {
      lines.push('  evidence:');
      for (const [k, v] of Object.entries(f.evidence)) {
        const val = typeof v === 'string' ? (v.length > 160 ? v.slice(0, 160) + '…' : v) : JSON.stringify(v);
        lines.push(`    ${k}: ${val}`);
      }
    }
    if (f.remediation) {
      lines.push('  remediation:');
      for (const ln of wrapText(f.remediation, 66)) lines.push(`    ${ln}`);
    }
    lines.push('');
  }

  lines.push(`diffed at ${result.diffAt}`);
  lines.push('');
  return lines.join('\n');
}

function wrapText(text, width) {
  const words = text.split(/\s+/);
  const out = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      if (line) out.push(line);
      line = w;
    } else {
      line = (line + ' ' + w).trim();
    }
  }
  if (line) out.push(line);
  return out;
}
