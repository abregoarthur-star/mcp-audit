// Tools whose names suggest they return sensitive data without obvious access controls.

const SENSITIVE_NAMES = [
  { regex: /^(get|read|fetch|list|dump|export)[_-]?(env|environment|secret|secrets|credentials?|tokens?|keys?|passwords?|vault)/i, kind: 'credentials/secrets' },
  { regex: /(env|environment|secret|secrets|credentials?|tokens?|keys?|passwords?|vault)$/i, kind: 'credentials/secrets' },
  { regex: /(get|read|fetch|list)[_-]?(users?|accounts?|sessions?|cookies)/i, kind: 'identity / session' },
  { regex: /(history|log|logs|audit)$/i, kind: 'history / logs (potential sensitive context)' },
  { regex: /(private|internal)[_-]?key/i, kind: 'private key' },
];

export const sensitiveOutput = {
  id: 'sensitive-output',
  scope: 'item',
  check(target) {
    if (target.kind !== 'tool') return [];
    const tool = target.tool;
    const findings = [];

    for (const { regex, kind } of SENSITIVE_NAMES) {
      if (regex.test(tool.name)) {
        findings.push({
          ruleId: 'sensitive-output',
          severity: 'high',
          title: `Tool "${tool.name}" likely returns ${kind}`,
          description:
            `The tool name suggests it returns ${kind}. If exposed to a host LLM, any prompt-injection ` +
            `that reaches this server can ask for the data and any other server in the session that has ` +
            `network egress can exfiltrate it. Tools that surface secrets should require explicit, ` +
            `per-call human approval and avoid being callable in autonomous loops.`,
          evidence: { name: tool.name, classification: kind },
          target: { kind: 'tool', name: tool.name },
          remediation:
            'Avoid exposing sensitive readers as MCP tools when possible. If required, gate them behind ' +
            'explicit user approval at call time, scope them to specific resources rather than wildcards, ' +
            'and audit-log every invocation.',
          references: ['https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/'],
        });
        break;
      }
    }
    return findings;
  },
};
