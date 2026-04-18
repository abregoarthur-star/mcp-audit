import { connect } from './connectors/index.js';
import { runRules, SEVERITY_ORDER } from './rules/index.js';

export { connect, runRules, SEVERITY_ORDER };

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
    findings,
    summary: {
      total: findings.length,
      bySeverity: counts,
    },
  };
}
