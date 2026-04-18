// mcp-audit diff — detect rug-pulls and drift between two MCP server surfaces.
//
// Loads two manifests (or any object with a `tools` array) and classifies
// each structural change by security impact. New tools that introduce a
// capability class the server didn't have before are CRITICAL (a classic
// supply-chain-style escalation). Schema widening and readOnlyHint removal
// are HIGH. Removals and cosmetic description edits are MEDIUM / LOW.
import { readFile } from 'node:fs/promises';

// Capability classification reused conceptually from unsafe-tool-combos
// (but inlined here so the diff module has no cross-rule dependency).
const VERBS_EXEC = new Set(['exec','execute','run','shell','bash','sh','cmd','spawn','subprocess']);
const STRONG_EXEC = new Set(['shell','bash','cmd','exec','execute','spawn','subprocess']);
const VERBS_READ = new Set(['read','get','list','cat','tail','head','stat','open','load','fetch','show','find','search','tree','describe']);
const VERBS_WRITE = new Set(['write','create','save','put','append','edit','modify','update','move','copy','delete','remove','rm','unlink','mkdir','rmdir']);
const SEND_VERBS = new Set(['send','post','publish','upload','notify','dispatch','push','call','invoke','trigger','make','request']);
const NOUNS_FILE = new Set(['file','files','dir','directory','directories','folder','folders','path','paths','disk']);
const NOUNS_SECRET = new Set(['env','envvar','secret','secrets','credential','credentials','token','tokens','key','keys','password','passwords','vault']);
const SERVICES_NETWORK = new Set(['telegram','slack','discord','email','mail','smtp','webhook','url','http','https','api']);
const ANALYTICS = new Set(['data','trend','trends','stat','stats','count','counts','summary','aggregate','distribution','analytics','metric','metrics']);

function tokenize(name) {
  if (!name) return [];
  return name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
const has = (set, tokens) => tokens.some(t => set.has(t));

function classifyTool(tool) {
  const tokens = tokenize(tool.name);
  const caps = new Set();
  if (has(STRONG_EXEC, tokens) || (tokens.includes('command') && has(VERBS_EXEC, tokens))) caps.add('shell_exec');
  if (has(VERBS_READ, tokens) && has(NOUNS_FILE, tokens)) caps.add('file_read');
  if (has(VERBS_WRITE, tokens) && has(NOUNS_FILE, tokens)) caps.add('file_write');
  if (has(VERBS_READ, tokens) && has(NOUNS_SECRET, tokens) && !has(ANALYTICS, tokens)) caps.add('secret_read');
  if (has(SEND_VERBS, tokens) && has(SERVICES_NETWORK, tokens)) caps.add('network_out');
  if (tokens.includes('download') || tokens.includes('upload')) caps.add('network_out');
  if (tokens.includes('http') && has(new Set(['request','post','put','delete','call','make']), tokens)) caps.add('network_out');
  return caps;
}

function aggregateCaps(tools) {
  const agg = new Set();
  for (const t of tools) for (const c of classifyTool(t)) agg.add(c);
  return agg;
}

const INJECTION_PATTERNS = [
  /ignore (?:all |the )?(?:previous|prior|above)/i,
  /(?:^|\n)(?:system|assistant|user)\s*:/i,
  /<\/?(?:system|instruction|admin|root)>/i,
  /you are now/i,
  /forget everything/i,
];
function hasInjectionMarker(text) {
  return INJECTION_PATTERNS.some(r => r.test(text));
}

function schemaHasPermissive(schema) {
  const s = JSON.stringify(schema || {});
  return /"additionalProperties"\s*:\s*true/.test(s);
}

function compareTool(before, after) {
  const changes = [];

  // Description
  const bDesc = (before.description || '').trim();
  const aDesc = (after.description || '').trim();
  if (bDesc !== aDesc) {
    const aHasInjection = hasInjectionMarker(aDesc);
    const bHasInjection = hasInjectionMarker(bDesc);
    if (aHasInjection && !bHasInjection) {
      changes.push({
        severity: 'critical',
        ruleId: 'diff/description-injection-added',
        title: `Prompt-injection markers appeared in description`,
        evidence: { before: bDesc.slice(0, 120), after: aDesc.slice(0, 300) },
      });
    } else if (bDesc.length > 0 && Math.abs(aDesc.length - bDesc.length) / bDesc.length > 0.25) {
      changes.push({
        severity: 'high',
        ruleId: 'diff/description-rewritten',
        title: `Description materially rewritten (${bDesc.length} → ${aDesc.length} chars)`,
        evidence: { before: bDesc.slice(0, 120), after: aDesc.slice(0, 300) },
      });
    } else {
      changes.push({
        severity: 'low',
        ruleId: 'diff/description-edited',
        title: `Description edited`,
        evidence: { before: bDesc.slice(0, 120), after: aDesc.slice(0, 300) },
      });
    }
  }

  // Schema
  const bSchemaStr = JSON.stringify(before.inputSchema || {});
  const aSchemaStr = JSON.stringify(after.inputSchema || {});
  if (bSchemaStr !== aSchemaStr) {
    const bPerm = schemaHasPermissive(before.inputSchema);
    const aPerm = schemaHasPermissive(after.inputSchema);
    if (aPerm && !bPerm) {
      changes.push({
        severity: 'high',
        ruleId: 'diff/schema-widened',
        title: `inputSchema widened: additionalProperties now true`,
        evidence: {},
      });
    } else {
      const bRequired = new Set(before.inputSchema?.required || []);
      const aRequired = new Set(after.inputSchema?.required || []);
      const droppedRequired = [...bRequired].filter(x => !aRequired.has(x));
      if (droppedRequired.length > 0) {
        changes.push({
          severity: 'medium',
          ruleId: 'diff/required-dropped',
          title: `Required parameters dropped: ${droppedRequired.join(', ')}`,
          evidence: { dropped: droppedRequired },
        });
      } else {
        changes.push({
          severity: 'low',
          ruleId: 'diff/schema-edited',
          title: `inputSchema edited`,
          evidence: {},
        });
      }
    }
  }

  // Annotations — readOnlyHint flip
  const bRO = before.annotations?.readOnlyHint;
  const aRO = after.annotations?.readOnlyHint;
  if (bRO === true && aRO !== true) {
    changes.push({
      severity: 'high',
      ruleId: 'diff/readonly-revoked',
      title: `readOnlyHint removed — tool may now mutate state`,
      evidence: { before: bRO, after: aRO },
    });
  }

  // Capability drift on the same-named tool
  const bCaps = classifyTool(before);
  const aCaps = classifyTool(after);
  const newCaps = [...aCaps].filter(c => !bCaps.has(c));
  if (newCaps.length > 0) {
    changes.push({
      severity: 'critical',
      ruleId: 'diff/tool-capability-expanded',
      title: `Tool now carries new capability class(es): ${newCaps.join(', ')}`,
      evidence: { before: [...bCaps], after: [...aCaps], added: newCaps },
    });
  }

  return changes;
}

async function loadSurface(spec) {
  if (typeof spec === 'string') {
    const raw = await readFile(spec, 'utf8');
    return JSON.parse(raw);
  }
  return spec;
}

function normalize(surface) {
  // Accept both extracted manifests and audit reports — they both carry `tools`.
  // Audit reports nest under `server.tools` in some formats; fall back to top-level.
  if (Array.isArray(surface?.tools)) return surface;
  if (Array.isArray(surface?.server?.tools)) return { ...surface, tools: surface.server.tools };
  return { tools: [] };
}

export async function diff(baselineSpec, currentSpec) {
  const baseline = normalize(await loadSurface(baselineSpec));
  const current  = normalize(await loadSurface(currentSpec));

  const byName = (arr) => new Map(arr.map(t => [t.name, t]));
  const bMap = byName(baseline.tools);
  const cMap = byName(current.tools);

  const bCaps = aggregateCaps(baseline.tools);
  const cCaps = aggregateCaps(current.tools);

  const toolsAdded = [];
  const toolsRemoved = [];
  const toolsChanged = [];

  for (const [name, tool] of cMap) {
    if (!bMap.has(name)) toolsAdded.push(tool);
    else {
      const changes = compareTool(bMap.get(name), tool);
      if (changes.length > 0) toolsChanged.push({ name, before: bMap.get(name), after: tool, changes });
    }
  }
  for (const [name, tool] of bMap) {
    if (!cMap.has(name)) toolsRemoved.push(tool);
  }

  const findings = [];

  for (const tool of toolsAdded) {
    const caps = classifyTool(tool);
    const novelCaps = [...caps].filter(c => !bCaps.has(c));
    if (novelCaps.length > 0) {
      findings.push({
        severity: 'critical',
        ruleId: 'diff/tool-added-with-new-capability',
        title: `New tool "${tool.name}" introduces capability class(es) the server didn't have: ${novelCaps.join(', ')}`,
        evidence: { name: tool.name, caps: [...caps], novelCaps },
        target: { kind: 'tool', name: tool.name },
        remediation:
          'A silent capability expansion is a classic rug-pull vector. Verify the maintainer intended this, ' +
          'that the tool is audited, and that session-level trust assumptions about this server still hold.',
      });
    } else {
      findings.push({
        severity: 'medium',
        ruleId: 'diff/tool-added',
        title: `New tool added: ${tool.name}`,
        evidence: { name: tool.name, caps: [...caps] },
        target: { kind: 'tool', name: tool.name },
      });
    }
  }

  for (const tool of toolsRemoved) {
    findings.push({
      severity: 'medium',
      ruleId: 'diff/tool-removed',
      title: `Tool removed: ${tool.name}`,
      evidence: { name: tool.name },
      target: { kind: 'tool', name: tool.name },
    });
  }

  for (const change of toolsChanged) {
    for (const c of change.changes) {
      findings.push({
        ...c,
        evidence: { name: change.name, ...c.evidence },
        target: { kind: 'tool', name: change.name },
      });
    }
  }

  // Server-level capability drift summary
  const serverNovelCaps = [...cCaps].filter(c => !bCaps.has(c));
  if (serverNovelCaps.length > 0) {
    findings.push({
      severity: 'high',
      ruleId: 'diff/server-capability-drift',
      title: `Server gained capability class(es): ${serverNovelCaps.join(', ')}`,
      evidence: { beforeCaps: [...bCaps], afterCaps: [...cCaps], added: serverNovelCaps },
      target: { kind: 'server' },
    });
  }

  const bySeverity = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});

  return {
    diffAt: new Date().toISOString(),
    baseline: {
      name: baseline.server?.name || '(baseline)',
      tools: baseline.tools.length,
      caps: [...bCaps],
    },
    current: {
      name: current.server?.name || '(current)',
      tools: current.tools.length,
      caps: [...cCaps],
    },
    changes: {
      added: toolsAdded.length,
      removed: toolsRemoved.length,
      changed: toolsChanged.length,
    },
    findings,
    summary: { total: findings.length, bySeverity },
  };
}
