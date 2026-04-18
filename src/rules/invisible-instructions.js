// Detect invisible characters in descriptions: zero-width chars, RTL overrides, control chars,
// or large base64-looking blobs that may hide instructions from human reviewers but are still
// fed to the LLM.
// References:
//   - https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/
//   - "ASCII Smuggler" / Unicode Tag attacks

const ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;
const UNICODE_TAGS = /[\u{E0000}-\u{E007F}]/gu;
const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F]/g;
const BASE64_BLOB = /[A-Za-z0-9+/=]{120,}/;

function collectStrings(target) {
  const out = [];
  if (target.kind === 'tool') {
    out.push({ field: 'description', text: target.tool.description || '' });
    if (target.tool.inputSchema) walk(target.tool.inputSchema, 'inputSchema', out);
  } else if (target.kind === 'resource') {
    out.push({ field: 'description', text: target.resource.description || '' });
    out.push({ field: 'name', text: target.resource.name || '' });
  } else if (target.kind === 'prompt') {
    out.push({ field: 'description', text: target.prompt.description || '' });
  }
  return out;
}

function walk(obj, prefix, out) {
  if (!obj) return;
  if (typeof obj === 'string') {
    out.push({ field: prefix, text: obj });
    return;
  }
  if (typeof obj !== 'object') return;
  for (const [k, v] of Object.entries(obj)) {
    walk(v, `${prefix}.${k}`, out);
  }
}

function targetName(target) {
  if (target.kind === 'tool') return target.tool.name;
  if (target.kind === 'resource') return target.resource.uri || target.resource.name;
  if (target.kind === 'prompt') return target.prompt.name;
  return 'unknown';
}

export const invisibleInstructions = {
  id: 'invisible-instructions',
  scope: 'item',
  check(target) {
    const findings = [];
    const fields = collectStrings(target);

    for (const { field, text } of fields) {
      if (!text) continue;

      const zw = (text.match(ZERO_WIDTH) || []).length;
      const tags = (text.match(UNICODE_TAGS) || []).length;
      const ctrl = (text.match(CONTROL_CHARS) || []).length;
      const b64 = text.match(BASE64_BLOB);

      if (tags > 0) {
        findings.push({
          ruleId: 'invisible-instructions',
          severity: 'critical',
          title: `Unicode Tag characters found in ${field} of ${target.kind} "${targetName(target)}"`,
          description:
            'Unicode Tag block (U+E0000-U+E007F) characters can encode invisible ASCII text that ' +
            'humans cannot see but the LLM still reads. This is the "ASCII Smuggler" attack used to ' +
            'inject hidden instructions through descriptions.',
          evidence: { field, tagCount: tags },
          target: { kind: target.kind, name: targetName(target) },
          remediation: 'Strip Unicode Tag characters before publishing the server. Treat their presence as a vulnerability indicator.',
          references: ['https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/'],
        });
      }
      if (zw > 2) {
        findings.push({
          ruleId: 'invisible-instructions',
          severity: 'high',
          title: `Zero-width characters in ${field} of ${target.kind} "${targetName(target)}"`,
          description:
            'Multiple zero-width / bidi-override characters in a description. These can hide instructions ' +
            'from a human reviewer while still being read by the LLM.',
          evidence: { field, count: zw },
          target: { kind: target.kind, name: targetName(target) },
          remediation: 'Strip zero-width characters from descriptions.',
          references: [],
        });
      }
      if (ctrl > 0) {
        findings.push({
          ruleId: 'invisible-instructions',
          severity: 'medium',
          title: `Control characters in ${field} of ${target.kind} "${targetName(target)}"`,
          description: 'Non-printable control characters present in description text.',
          evidence: { field, count: ctrl },
          target: { kind: target.kind, name: targetName(target) },
          remediation: 'Remove control characters.',
          references: [],
        });
      }
      if (b64) {
        findings.push({
          ruleId: 'invisible-instructions',
          severity: 'low',
          title: `Possible base64-encoded blob in ${field} of ${target.kind} "${targetName(target)}"`,
          description:
            'Long base64-looking string in a description. This can be used to smuggle instructions ' +
            'past humans while the LLM may decode and act on it.',
          evidence: { field, sample: b64[0].slice(0, 40) + '…', length: b64[0].length },
          target: { kind: target.kind, name: targetName(target) },
          remediation: 'Replace inline base64 with a documented reference if legitimate.',
          references: [],
        });
      }
    }

    return findings;
  },
};
