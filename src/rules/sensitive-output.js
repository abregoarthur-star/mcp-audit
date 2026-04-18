// Tools whose names suggest they return sensitive data without obvious access controls.

// Patterns are intentionally narrow. Flag only when the name unambiguously
// surfaces sensitive data. Broad patterns like /logs$/ over-match public
// analytics surfaces (e.g. Certificate Transparency `list_ct_logs`, which is
// literally public by design).
// The "keys" pattern has been a recurring false-positive source. Names like
// `observability_keys` (metric dimensions), `get_publishable_keys` (explicitly
// public anon keys), and `list_object_keys` (S3/R2 object paths) all end in
// "keys" but are not secret-reveal tools. We now require a strong qualifier
// adjacent to "key" (api/secret/access/private/ssh/admin/auth), OR a
// standalone name like `get_secrets`.
const SENSITIVE_NAMES = [
  // Direct-name readers: get_env, list_secrets, dump_credentials, etc.
  { regex: /^(get|read|fetch|list|dump|export)[_-]?(env|environment|secret|secrets|credentials?|passwords?|vault)$/i, kind: 'credentials/secrets' },
  // Tokens/keys must have a sensitive qualifier. `auth_token`, `api_key`, but
  // NOT `observability_keys` or `publishable_keys`.
  { regex: /(^|[_-])(api|secret|access|private|admin|service|ssh|auth|bearer|refresh|session|oauth|jwt)[_-]?(tokens?|keys?)$/i, kind: 'credentials/secrets' },
  { regex: /(env|environment|vault|passwords?|credentials?)$/i, kind: 'credentials/secrets' },
  { regex: /(get|read|fetch|list)[_-]?(users?|accounts?|sessions?|cookies)$/i, kind: 'identity / session' },
  { regex: /(audit|access|activity|security|auth|login|signin)[_-]?logs?$/i, kind: 'audit/access logs' },
  { regex: /(chat|conversation|command|shell|search|browse|user|visit)[_-]?history$/i, kind: 'user history (PII)' },
  { regex: /(private|internal|ssh)[_-]?keys?$/i, kind: 'private key' },
];

// Explicit allowlist: names that would otherwise match but are safe by design.
const SAFE_BY_DESIGN = /^(publishable|public|anon|anonymous|test)[_-]|[_-](publishable|public|anon|anonymous)[_-]|[_-](publishable|public|anon|anonymous)_keys?$/i;

export const sensitiveOutput = {
  id: 'sensitive-output',
  scope: 'item',
  check(target) {
    if (target.kind !== 'tool') return [];
    const tool = target.tool;
    const findings = [];

    if (SAFE_BY_DESIGN.test(tool.name)) return findings;

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
