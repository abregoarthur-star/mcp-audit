// Detect prompt-injection patterns embedded in tool/prompt/resource descriptions.
// MCP servers can attack the host LLM via descriptions the model will read.
// References:
//   - https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
//   - OWASP LLM01: Prompt Injection

const INJECTION_PATTERNS = [
  { regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i, label: 'instruction override' },
  { regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)/i, label: 'instruction override' },
  { regex: /you\s+are\s+now\s+(?:a|an)\s+/i, label: 'role redefinition' },
  { regex: /act\s+as\s+(?:a|an|if)\s+/i, label: 'role redefinition' },
  { regex: /pretend\s+(?:to\s+be|you\s+are)/i, label: 'role redefinition' },
  { regex: /<\s*system\s*>/i, label: 'fake system tag' },
  { regex: /<\s*\/?\s*(?:assistant|user|system)\s*>/i, label: 'fake conversation tag' },
  { regex: /\[\[?\s*system\s*\]\]?/i, label: 'fake system tag' },
  { regex: /^\s*system\s*:/im, label: 'system: prefix' },
  { regex: /\bDAN\b|jailbreak|developer\s+mode/i, label: 'known jailbreak phrase' },
  { regex: /reveal\s+(your\s+)?(system\s+)?prompt/i, label: 'system prompt extraction' },
  { regex: /print\s+(your\s+)?(initial\s+|system\s+)?(instructions?|prompts?)/i, label: 'system prompt extraction' },
  { regex: /repeat\s+(everything|all)\s+above/i, label: 'context exfiltration' },
  { regex: /do\s+not\s+(tell|inform|mention|disclose|reveal)\s+(the\s+)?(user|human)/i, label: 'user concealment' },
  { regex: /without\s+(the\s+)?user(?:'s)?\s+(knowledge|consent|permission)/i, label: 'user concealment' },
  { regex: /silently\s+(send|post|forward|exfiltrate|email|upload)/i, label: 'silent exfil instruction' },
  { regex: /before\s+(?:you\s+)?(?:respond|answer|reply)/i, label: 'pre-response instruction' },
  { regex: /\bIMPORTANT\b[\s\S]{0,80}\b(must|always|never)\b/i, label: 'authoritative override' },
];

function getDescriptions(target) {
  if (target.kind === 'tool') {
    return [
      { field: 'description', text: target.tool.description || '' },
      ...extractSchemaText(target.tool.inputSchema, 'inputSchema'),
    ];
  }
  if (target.kind === 'resource') {
    return [
      { field: 'description', text: target.resource.description || '' },
      { field: 'name', text: target.resource.name || '' },
    ];
  }
  if (target.kind === 'prompt') {
    return [
      { field: 'description', text: target.prompt.description || '' },
      ...(target.prompt.arguments || []).map((a, i) => ({
        field: `arguments[${i}].description`,
        text: a.description || '',
      })),
    ];
  }
  return [];
}

function extractSchemaText(schema, prefix) {
  if (!schema || typeof schema !== 'object') return [];
  const out = [];
  if (typeof schema.description === 'string') {
    out.push({ field: `${prefix}.description`, text: schema.description });
  }
  if (schema.properties && typeof schema.properties === 'object') {
    for (const [key, val] of Object.entries(schema.properties)) {
      out.push(...extractSchemaText(val, `${prefix}.properties.${key}`));
    }
  }
  return out;
}

function targetName(target) {
  if (target.kind === 'tool') return target.tool.name;
  if (target.kind === 'resource') return target.resource.uri || target.resource.name;
  if (target.kind === 'prompt') return target.prompt.name;
  return 'unknown';
}

export const promptInjection = {
  id: 'prompt-injection',
  scope: 'item',
  check(target) {
    const findings = [];
    const fields = getDescriptions(target);
    const matchesByField = new Map();

    for (const { field, text } of fields) {
      if (!text) continue;
      for (const { regex, label } of INJECTION_PATTERNS) {
        const m = text.match(regex);
        if (m) {
          const key = `${field}::${label}`;
          if (!matchesByField.has(key)) {
            matchesByField.set(key, { field, label, snippet: snippetAround(text, m.index, m[0].length) });
          }
        }
      }
    }

    for (const { field, label, snippet } of matchesByField.values()) {
      findings.push({
        ruleId: 'prompt-injection',
        severity: 'critical',
        title: `Prompt-injection pattern in ${target.kind} ${field}: ${label}`,
        description:
          `The ${target.kind} "${targetName(target)}" contains text that resembles a prompt-injection ` +
          `payload targeting the host LLM. MCP clients render tool/prompt/resource descriptions to the ` +
          `model verbatim, so a malicious server can manipulate the agent's behavior without the user seeing it.`,
        evidence: { field, snippet, pattern: label },
        target: { kind: target.kind, name: targetName(target) },
        remediation:
          'Strip instructional language from descriptions. Descriptions should describe what the tool ' +
          'does, not issue commands to the LLM. If you must include literal examples of injection ' +
          'patterns (e.g. for testing), encode/escape them so the model does not parse them as instructions.',
        references: [
          'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
          'https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks',
        ],
      });
    }

    return findings;
  },
};

function snippetAround(text, index, len) {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + len + 30);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return `${prefix}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${suffix}`;
}
