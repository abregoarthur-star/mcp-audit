// A single MCP server exposing tools across many unrelated domains has a large blast radius.
// One prompt-injection that lands here = full kit.

const DOMAIN_PATTERNS = {
  filesystem: /(file|fs|disk|directory|folder|path)/i,
  network:    /(http|fetch|webhook|email|slack|telegram|discord|sms|notify|publish|post|send|upload)/i,
  shell:      /(exec|shell|bash|cmd|spawn|process|run[_-]?command)/i,
  database:   /(sql|query|insert|select|update|delete|table|row|schema|postgres|mysql|sqlite|redis|mongo)/i,
  cloud:      /(s3|bucket|aws|gcp|azure|cloudflare|kv|d1|r2|hyperdrive)/i,
  identity:   /(user|account|session|cookie|login|auth|password|token|secret)/i,
  vcs:        /(git|github|gitlab|commit|branch|pull[_-]?request|merge|push)/i,
  payments:   /(payment|charge|invoice|subscription|stripe|checkout|refund)/i,
};

function classifyTool(tool) {
  const text = `${tool.name} ${tool.description || ''}`;
  const domains = new Set();
  for (const [domain, regex] of Object.entries(DOMAIN_PATTERNS)) {
    if (regex.test(text)) domains.add(domain);
  }
  return domains;
}

export const excessiveScope = {
  id: 'excessive-scope',
  scope: 'server',
  check(target) {
    const server = target.server;
    if (!server.tools?.length) return [];

    const domainTools = new Map();
    for (const tool of server.tools) {
      for (const d of classifyTool(tool)) {
        if (!domainTools.has(d)) domainTools.set(d, []);
        domainTools.get(d).push(tool.name);
      }
    }

    if (domainTools.size >= 4) {
      return [{
        ruleId: 'excessive-scope',
        severity: 'medium',
        title: `Server spans ${domainTools.size} unrelated domains: ${[...domainTools.keys()].join(', ')}`,
        description:
          'A single MCP server provides tools across many unrelated capability domains. This concentrates ' +
          'risk: one prompt-injection that gets through gives the attacker the union of all capabilities. ' +
          'Splitting by domain lets the host enforce different trust levels and approval flows per server.',
        evidence: Object.fromEntries([...domainTools.entries()].map(([k, v]) => [k, v])),
        target: { kind: 'server', name: server.name || 'unknown' },
        remediation:
          'Split the server into smaller, domain-scoped servers. The host can compose them; the blast ' +
          'radius of any single server compromise stays bounded.',
        references: [],
      }];
    }
    return [];
  },
};
