// Detect dangerous tool combinations on a single MCP server.
// A server that exposes both file-write AND network-egress AND credential-read
// is a one-stop exfiltration kit for any prompt-injection attack.

const CAPABILITY_PATTERNS = {
  file_read:    /^(read[_-]?file|cat|get[_-]?file|fs[_-]?read|file[_-]?get|read|fetch[_-]?file)$/i,
  file_write:   /(write|create|save|put|append|patch)[_-]?(file|fs|to[_-]?disk)/i,
  shell_exec:   /(exec|run|shell|bash|cmd|spawn|system|eval|process)/i,
  network_out:  /(fetch|http|request|webhook|post|send|upload|publish|email|notify|telegram|slack|discord)/i,
  secret_read:  /(env|secret|credential|token|key|password|vault)/i,
  db_write:     /(insert|delete|drop|update|truncate|alter|migrate)/i,
};

function classifyTool(tool) {
  const name = tool.name || '';
  const desc = (tool.description || '').toLowerCase();
  const text = `${name} ${desc}`;
  const caps = new Set();
  for (const [cap, regex] of Object.entries(CAPABILITY_PATTERNS)) {
    if (regex.test(text)) caps.add(cap);
  }
  return caps;
}

const DANGEROUS_COMBOS = [
  {
    caps: ['shell_exec', 'network_out'],
    severity: 'critical',
    title: 'Shell execution + network egress on same server',
    description:
      'A single server provides both arbitrary command execution and outbound network capability. ' +
      'Any prompt-injection that lands here can run a command and exfiltrate the output in one hop.',
  },
  {
    caps: ['file_read', 'network_out'],
    severity: 'high',
    title: 'File read + network egress on same server',
    description:
      'File-read paired with outbound network is a complete exfiltration primitive. Combined with ' +
      'a prompt injection on any other server in the session, an attacker can read local files and ' +
      'send them to an attacker-controlled endpoint.',
  },
  {
    caps: ['secret_read', 'network_out'],
    severity: 'critical',
    title: 'Credential/secret access + network egress',
    description:
      'Tools that read secrets (env vars, tokens, keys) on the same server as outbound network calls ' +
      'is a credential-exfil primitive.',
  },
  {
    caps: ['file_write', 'shell_exec'],
    severity: 'high',
    title: 'File write + shell execution',
    description:
      'Write a script, then execute it. Classic local-RCE pivot path.',
  },
];

export const unsafeToolCombos = {
  id: 'unsafe-tool-combos',
  scope: 'server',
  check(target) {
    const server = target.server;
    if (!server.tools?.length) return [];

    const serverCaps = new Map();
    for (const tool of server.tools) {
      for (const cap of classifyTool(tool)) {
        if (!serverCaps.has(cap)) serverCaps.set(cap, []);
        serverCaps.get(cap).push(tool.name);
      }
    }

    const findings = [];
    for (const combo of DANGEROUS_COMBOS) {
      if (combo.caps.every(c => serverCaps.has(c))) {
        const evidence = Object.fromEntries(combo.caps.map(c => [c, serverCaps.get(c)]));
        findings.push({
          ruleId: 'unsafe-tool-combos',
          severity: combo.severity,
          title: combo.title,
          description: combo.description,
          evidence,
          target: { kind: 'server', name: server.name || 'unknown' },
          remediation:
            'Split capabilities across separate MCP servers with separate trust boundaries. The host ' +
            'agent can compose them, but a compromise of one server should not yield the full kill chain. ' +
            'Where possible, gate sensitive tools behind explicit user approval at call time.',
          references: [
            'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
            'https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/',
          ],
        });
      }
    }
    return findings;
  },
};
