// Rule registry. Each rule is a pure function: (target, ctx) -> Finding[]
// target shapes:
//   { kind: 'tool',     tool: { name, description, inputSchema } }
//   { kind: 'resource', resource: { uri, name, description, mimeType } }
//   { kind: 'prompt',   prompt: { name, description, arguments } }
//   { kind: 'server',   server: { name, version, transport, auth, tools, resources, prompts } }
//
// Finding shape:
//   { ruleId, severity, title, description, evidence, target, remediation, references }

import { promptInjection } from './prompt-injection.js';
import { toolPoisoning } from './tool-poisoning.js';
import { invisibleInstructions } from './invisible-instructions.js';
import { unsafeToolCombos } from './unsafe-tool-combos.js';
import { schemaPermissiveness } from './schema-permissiveness.js';
import { sensitiveOutput } from './sensitive-output.js';
import { destructiveNoConfirm } from './destructive-no-confirm.js';
import { unauthenticatedServer } from './unauthenticated-server.js';
import { excessiveScope } from './excessive-scope.js';

export const RULES = [
  promptInjection,
  toolPoisoning,
  invisibleInstructions,
  unsafeToolCombos,
  schemaPermissiveness,
  sensitiveOutput,
  destructiveNoConfirm,
  unauthenticatedServer,
  excessiveScope,
];

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function runRules(server) {
  const findings = [];
  const ctx = { server };

  for (const rule of RULES) {
    if (rule.scope === 'server') {
      findings.push(...(rule.check({ kind: 'server', server }, ctx) || []));
      continue;
    }
    for (const tool of server.tools || []) {
      findings.push(...(rule.check({ kind: 'tool', tool }, ctx) || []));
    }
    for (const resource of server.resources || []) {
      findings.push(...(rule.check({ kind: 'resource', resource }, ctx) || []));
    }
    for (const prompt of server.prompts || []) {
      findings.push(...(rule.check({ kind: 'prompt', prompt }, ctx) || []));
    }
  }

  return findings.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
}
