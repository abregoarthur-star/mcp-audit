import kleur from 'kleur';

const SEV_STYLE = {
  critical: kleur.bgRed().white().bold,
  high:     kleur.red().bold,
  medium:   kleur.yellow().bold,
  low:      kleur.cyan,
  info:     kleur.gray,
};

function sevTag(sev) {
  const style = SEV_STYLE[sev] || ((s) => s);
  return style(` ${sev.toUpperCase().padEnd(8)} `);
}

export function renderTerminal(report) {
  const out = [];
  const { server, summary, findings } = report;

  out.push('');
  out.push(kleur.bold().underline(`MCP Audit Report`));
  out.push(`Server:    ${kleur.cyan(server.name)} ${server.version ? kleur.gray('v' + server.version) : ''}`);
  out.push(`Transport: ${server.transport}${server.url ? ' · ' + server.url : ''}`);
  if (server.auth) {
    const authLabel = server.auth.kind + (server.auth.required ? ' (required)' : '');
    out.push(`Auth:      ${authLabel}`);
  }
  out.push(`Surface:   ${server.counts.tools} tools · ${server.counts.resources} resources · ${server.counts.prompts} prompts`);
  out.push('');

  out.push(kleur.bold('Summary'));
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const n = summary.bySeverity[sev] || 0;
    if (n > 0) {
      const style = SEV_STYLE[sev] || ((s) => s);
      out.push(`  ${style(sev.padEnd(9))} ${n}`);
    }
  }
  if (summary.total === 0) {
    out.push(kleur.green('  No findings.'));
  }
  out.push('');

  if (findings.length > 0) {
    out.push(kleur.bold(`Findings (${findings.length})`));
    out.push(kleur.gray('─'.repeat(70)));
    for (const f of findings) {
      out.push(`${sevTag(f.severity)} ${kleur.bold(f.title)}`);
      out.push(kleur.gray(`  rule: ${f.ruleId}  ·  target: ${f.target.kind}/${f.target.name}`));
      out.push(`  ${wrap(f.description, 70, '  ')}`);
      if (f.evidence && Object.keys(f.evidence).length > 0) {
        out.push(kleur.gray('  evidence:'));
        for (const [k, v] of Object.entries(f.evidence)) {
          const val = typeof v === 'string' ? v : JSON.stringify(v);
          out.push(kleur.gray(`    ${k}: ${truncate(val, 200)}`));
        }
      }
      if (f.remediation) {
        out.push(kleur.gray('  remediation:'));
        out.push(kleur.gray(`    ${wrap(f.remediation, 70, '    ')}`));
      }
      if (f.references?.length) {
        out.push(kleur.gray('  refs:'));
        for (const ref of f.references) out.push(kleur.gray(`    - ${ref}`));
      }
      out.push('');
    }
  }

  out.push(kleur.gray(`audited at ${report.auditedAt}`));
  out.push('');
  return out.join('\n');
}

function wrap(text, width, indent = '') {
  const words = text.split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? line + ' ' + w : w;
    }
  }
  if (line) lines.push(line);
  return lines.join('\n' + indent);
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}
