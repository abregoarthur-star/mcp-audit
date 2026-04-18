// Detect dangerous tool combinations on a single MCP server.
// A server that exposes both file-write AND network-egress AND credential-read
// is a one-stop exfiltration kit for any prompt-injection attack.

// Classify capabilities by TOOL NAME ONLY. Free-text descriptions are too
// noisy (e.g. "file system" would match /system/). Tool names are the stable
// contract; they follow predictable verb_noun patterns in snake_case, kebab,
// or camelCase.
//
// Strategy: tokenize the name, then require a verb token AND (where relevant)
// an object token. This avoids the "read" alone → file_read trap and the
// "fetch the list" false positive, while still catching both orderings like
// send_telegram and telegram_send.

const VERBS_EXEC = new Set(['exec','execute','run','shell','bash','sh','cmd','spawn','subprocess']);
const STRONG_EXEC_TOKENS = new Set(['shell','bash','cmd','exec','execute','spawn','subprocess']);
const VERBS_READ = new Set(['read','get','list','cat','tail','head','stat','open','load','fetch','show','find','search','tree','describe']);
const VERBS_WRITE = new Set(['write','create','save','put','append','edit','modify','update','move','copy','delete','remove','rm','unlink','mkdir','rmdir','chmod','chown']);
const VERBS_EGRESS = new Set(['send','post','publish','upload','notify','dispatch','push','call','invoke','trigger']);
const NOUNS_FILE = new Set(['file','files','dir','directory','directories','folder','folders','path','paths','disk']);
const NOUNS_SECRET = new Set(['env','envvar','secret','secrets','credential','credentials','token','tokens','key','keys','password','passwords','vault','apikey']);
const SERVICES_NETWORK = new Set(['telegram','slack','discord','email','mail','smtp','webhook','url','http','https','api','sms','twilio','pagerduty','teams','zoom']);
const VERBS_DB_WRITE = new Set(['insert','update','delete','drop','truncate','alter','migrate']);
const NOUNS_DB = new Set(['row','rows','table','tables','schema','db','database','record','records']);

function tokenize(name) {
  if (!name) return [];
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // camelCase → camel Case
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function has(set, tokens) {
  for (const t of tokens) if (set.has(t)) return true;
  return false;
}

function classifyTool(tool) {
  const tokens = tokenize(tool.name);
  const caps = new Set();
  if (tokens.length === 0) return caps;

  // Shell execution — any strong exec verb or a verb+command/shell combination
  if (has(STRONG_EXEC_TOKENS, tokens) || tokens.includes('command') && has(VERBS_EXEC, tokens)) {
    caps.add('shell_exec');
  }

  // File read — read-verb + file-noun
  if (has(VERBS_READ, tokens) && has(NOUNS_FILE, tokens)) caps.add('file_read');

  // File write — write-verb + file-noun (or verb alone if unmistakable like mkdir/rmdir)
  if (has(VERBS_WRITE, tokens) && has(NOUNS_FILE, tokens)) caps.add('file_write');
  if (tokens.includes('mkdir') || tokens.includes('rmdir')) caps.add('file_write');

  // Secret read — read-verb + secret-noun, UNLESS the name also contains
  // analytics/aggregation tokens (e.g. `get_leaked_credentials_data` reports
  // trends, not credential contents).
  const ANALYTICS_TOKENS = new Set(['data','trend','trends','stat','stats','statistics','count','counts','summary','aggregate','aggregated','distribution','analytics','insight','insights','observation','observations','metric','metrics']);
  if (has(VERBS_READ, tokens) && has(NOUNS_SECRET, tokens) && !has(ANALYTICS_TOKENS, tokens)) {
    caps.add('secret_read');
  }

  // Network egress — requires an explicit SEND-class action.
  // Read-style idioms (`get_http_data`, `list_webhooks`) are analytics reads,
  // not capability-carrying outbound calls.
  const SEND_VERBS = new Set(['send','post','publish','upload','notify','dispatch','push','call','invoke','trigger','make','request']);
  if (has(SEND_VERBS, tokens) && has(SERVICES_NETWORK, tokens)) caps.add('network_out');
  if (tokens.includes('download') || tokens.includes('upload')) caps.add('network_out');
  if (tokens.includes('http') && has(new Set(['request','post','put','delete','call','make']), tokens)) caps.add('network_out');
  if (tokens.includes('fetch') && (tokens.includes('url') || tokens.includes('http'))) caps.add('network_out');
  if (tokens.includes('webhook') && has(SEND_VERBS, tokens)) caps.add('network_out');

  // DB write — mutation verb + db noun, or `execute_sql`/`apply_migration` idioms
  if (has(VERBS_DB_WRITE, tokens) && has(NOUNS_DB, tokens)) caps.add('db_write');
  if ((tokens.includes('execute') || tokens.includes('run')) && tokens.includes('sql')) caps.add('db_write');
  if (tokens.includes('apply') && tokens.includes('migration')) caps.add('db_write');

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
