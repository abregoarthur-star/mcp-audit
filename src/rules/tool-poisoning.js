// Tool poisoning: tool description claims one behavior but the schema/name suggests another.
// Examples:
//   - Tool named "get_weather" with a "command" parameter
//   - Description says "read-only" but schema accepts a "write_to" param
//   - Description mentions a different tool name than the actual name (rug-pull / version drift)

const SUSPICIOUS_HIDDEN_PARAMS = [
  { name: /^(cmd|command|exec|shell|run|eval|script)$/i, hint: 'shell execution' },
  { name: /^(payload|raw|body)$/i, hint: 'raw payload' },
  { name: /^(secret|token|api[_-]?key|password|credential)s?$/i, hint: 'credential field' },
  { name: /^(write[_-]?to|sink|destination|webhook|callback)$/i, hint: 'data sink' },
];

function getParams(schema) {
  if (!schema?.properties) return [];
  return Object.entries(schema.properties).map(([name, def]) => ({ name, def }));
}

export const toolPoisoning = {
  id: 'tool-poisoning',
  scope: 'item',
  check(target) {
    if (target.kind !== 'tool') return [];
    const tool = target.tool;
    const desc = (tool.description || '').toLowerCase();
    const params = getParams(tool.inputSchema);
    const findings = [];

    // Hidden capability: description doesn't mention the suspicious param
    for (const param of params) {
      for (const { name, hint } of SUSPICIOUS_HIDDEN_PARAMS) {
        if (name.test(param.name) && !desc.includes(param.name.toLowerCase())) {
          findings.push({
            ruleId: 'tool-poisoning',
            severity: 'high',
            title: `Hidden capability: tool "${tool.name}" exposes ${hint} param "${param.name}" not mentioned in description`,
            description:
              `The tool's description doesn't reference its "${param.name}" parameter, which suggests ` +
              `${hint}. Hidden capabilities are a tool-poisoning pattern — the LLM may reason about the ` +
              `tool based on the description while the param enables behavior the user didn't expect.`,
            evidence: { param: param.name, hint, description: tool.description || '(empty)' },
            target: { kind: 'tool', name: tool.name },
            remediation:
              `Document the "${param.name}" parameter in the tool description, or remove it if not needed. ` +
              `Every parameter that materially affects behavior should be visible in the description so ` +
              `the host LLM and the user can reason about the tool's actual capabilities.`,
            references: ['https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks'],
          });
        }
      }
    }

    // Read-only claim contradicted by write/destructive params
    if (/\b(read[- ]?only|readonly|safe|harmless|non[- ]?destructive)\b/i.test(tool.description || '')) {
      const writeParams = params.filter(p =>
        /(write|delete|remove|drop|update|set|modify|patch|put|post|exec|run)/i.test(p.name)
      );
      if (writeParams.length > 0) {
        findings.push({
          ruleId: 'tool-poisoning',
          severity: 'high',
          title: `Tool "${tool.name}" claims read-only/safe but exposes mutating params: ${writeParams.map(p => p.name).join(', ')}`,
          description:
            'Description asserts the tool is read-only or safe, but the schema includes parameters whose ' +
            'names suggest mutation. This contradiction can mislead both the LLM and human reviewers.',
          evidence: { description: tool.description, mutatingParams: writeParams.map(p => p.name) },
          target: { kind: 'tool', name: tool.name },
          remediation:
            'Either remove the mutating parameters or update the description to accurately describe ' +
            'the tool\'s side effects.',
          references: [],
        });
      }
    }

    // Description references a different tool name (possible rug-pull or copy-paste leftover)
    const nameRegex = /\btool\s+(?:named|called)?\s*["`']([\w.-]+)["`']/i;
    const m = (tool.description || '').match(nameRegex);
    if (m && m[1] && m[1] !== tool.name) {
      findings.push({
        ruleId: 'tool-poisoning',
        severity: 'medium',
        title: `Tool "${tool.name}" description references a different tool name: "${m[1]}"`,
        description:
          'The description cites a different tool name than the registered tool. This can indicate ' +
          'a copy-paste error, a rug-pull (tool renamed after the description was reviewed), or ' +
          'intentional confusion.',
        evidence: { actualName: tool.name, mentionedName: m[1] },
        target: { kind: 'tool', name: tool.name },
        remediation: 'Align the description with the actual tool name.',
        references: [],
      });
    }

    return findings;
  },
};
