// A single MCP server exposing tools across many unrelated domains has a large blast radius.
// One prompt-injection that lands here = full kit.
//
// Classification is TOKEN-BASED on the tool NAME only. Free-text descriptions
// are too noisy — words like "update", "process", "file system", or
// "subscription management" match capability keywords that have nothing to do
// with the tool's actual domain.

const DOMAIN_TOKENS = {
  filesystem: new Set(['file','files','fs','disk','directory','directories','folder','folders','path','paths','mkdir','rmdir']),
  network:    new Set(['http','https','webhook','email','mail','smtp','slack','telegram','discord','sms','twilio','pagerduty','teams']),
  shell:      new Set(['exec','execute','shell','bash','sh','cmd','spawn','subprocess']),
  database:   new Set(['sql','query','insert','postgres','mysql','sqlite','redis','mongo','db','database','table','tables','row','rows']),
  cloud:      new Set(['s3','bucket','buckets','aws','gcp','azure','cloudflare','kv','d1','r2','hyperdrive','lambda','worker','workers']),
  identity:   new Set(['user','users','account','accounts','session','sessions','cookie','cookies','login','signin','auth','authn','authz','password','passwords','vault']),
  vcs:        new Set(['git','github','gitlab','bitbucket','commit','commits','branch','branches','merge','rebase']),
  payments:   new Set(['payment','payments','charge','charges','invoice','invoices','stripe','checkout','refund','refunds']),
  messaging:  new Set(['message','messages','notify','publish','dispatch','send','post']),
  observability: new Set(['log','logs','metric','metrics','trace','traces','span','spans','alert','alerts']),
};

function tokenize(name) {
  if (!name) return [];
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function classifyTool(tool) {
  const tokens = tokenize(tool.name);
  const domains = new Set();
  for (const [domain, tokenSet] of Object.entries(DOMAIN_TOKENS)) {
    for (const t of tokens) {
      if (tokenSet.has(t)) { domains.add(domain); break; }
    }
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
