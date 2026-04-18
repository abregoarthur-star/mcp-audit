import { connect } from './connectors/index.js';
import { runRules, SEVERITY_ORDER } from './rules/index.js';
import { diff } from './diff.js';

export { connect, runRules, SEVERITY_ORDER, diff };

export async function audit(spec) {
  const server = await connect(spec);
  const findings = runRules(server);

  const counts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = findings.filter(f => f.severity === sev).length;
    return acc;
  }, {});

  return {
    auditedAt: new Date().toISOString(),
    server: {
      name: server.name,
      version: server.version,
      transport: server.transport,
      url: server.url,
      auth: server.auth,
      counts: {
        tools: server.tools.length,
        resources: server.resources.length,
        prompts: server.prompts.length,
      },
    },
    // Structural snapshot — preserved so the report itself can be used
    // as a baseline for `mcp-audit diff` without re-extraction.
    tools: server.tools.map(t => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: t.annotations,
    })),
    resources: server.resources.map(r => ({ uri: r.uri, name: r.name, description: r.description })),
    prompts: server.prompts.map(p => ({ name: p.name, description: p.description })),
    findings,
    summary: {
      total: findings.length,
      bySeverity: counts,
    },
  };
}
