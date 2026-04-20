// SARIF 2.1.0 reporter — emits the industry-standard format GitHub, Azure DevOps,
// GitLab, and most enterprise security tooling consume natively.
//
// When uploaded via github/codeql-action/upload-sarif@v3 in a workflow,
// findings surface in the PR Security tab + inline on Files Changed.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
// GitHub's supported subset: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

import pkg from '../../package.json' with { type: 'json' };

// Mirror the rule registry from src/rules/index.js — each SARIF rule entry
// documents what mcp-audit looks for and links to the repo for context.
const RULE_CATALOG = {
  'prompt-injection': {
    name: 'PromptInjection',
    short: 'Prompt-injection patterns in tool, resource, or prompt descriptions',
    full:
      'MCP clients render tool/prompt/resource descriptions to the host LLM verbatim. ' +
      'Text that resembles a prompt-injection payload (instruction overrides, role redefinition, ' +
      'system-prompt extraction, silent-exfiltration directives) can manipulate the agent without ' +
      'the user seeing it.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'invisible-instructions': {
    name: 'InvisibleInstructions',
    short: 'Invisible characters (Unicode Tags, zero-width, control) in descriptions',
    full:
      'Unicode Tag block characters (the "ASCII Smuggler" attack), zero-width characters, and ' +
      'embedded control characters hide instructions from human reviewers while the LLM still ' +
      'reads them. Any presence is a vulnerability indicator.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'tool-poisoning': {
    name: 'ToolPoisoning',
    short: 'Hidden capabilities or description-vs-schema contradictions',
    full:
      'Parameters not mentioned in the description, read-only claims contradicted by mutating params, ' +
      'or descriptions that cite a different tool name than the registered one. Signals a rug-pull ' +
      'or a tool whose actual capabilities are not what the model reasons about.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'unsafe-tool-combos': {
    name: 'UnsafeToolCombos',
    short: 'Lethal trifecta capability combinations on one server',
    full:
      'Shell execution + network egress, secret read + network egress, file read + network egress, ' +
      'or file write + shell execution on a single MCP server. Any prompt injection that lands on ' +
      'such a server can complete a full exfiltration or RCE chain in one hop.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'sensitive-output': {
    name: 'SensitiveOutput',
    short: 'Tool names suggesting sensitive data return (secrets, env, credentials)',
    full:
      'Tools that likely surface credentials, environment variables, tokens, sessions, or private ' +
      'keys. If exposed to a host LLM, any injection can request the data and any outbound-network ' +
      'tool on the same server can exfiltrate it.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'destructive-no-confirm': {
    name: 'DestructiveNoConfirm',
    short: 'Destructive tools without explicit confirmation parameter',
    full:
      'Tools named delete_*, drop_*, kill_*, reset_*, purge_*, etc., should accept a required ' +
      'confirmation flag ("confirm": true). Without it, prompt injection can invoke them with ' +
      'plausible arguments and the host has no schema-level second gate beyond its approval UI.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'schema-permissiveness': {
    name: 'SchemaPermissiveness',
    short: 'Unbounded or over-permissive input schemas',
    full:
      'Missing inputSchema, additionalProperties: true, unbounded string parameters on command-shaped ' +
      'surfaces, or object parameters without defined properties. Widens the attack surface and ' +
      'removes host-side ability to validate arguments before dispatch.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'unauthenticated-server': {
    name: 'UnauthenticatedServer',
    short: 'Remote HTTP/SSE server accepts unauthenticated connections',
    full:
      'Remote MCP servers should require authentication. Without it, anyone who can reach the URL ' +
      'can enumerate tools and invoke them. Combined with any data-egress tool, this is an open ' +
      'data path.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
  'excessive-scope': {
    name: 'ExcessiveScope',
    short: 'Single server spans many unrelated capability domains (large blast radius)',
    full:
      'A single MCP server exposing tools across filesystem + network + shell + database + identity ' +
      'concentrates risk. A compromise of one server yields the union of all its capabilities. Split ' +
      'by domain so the host can enforce different trust levels per server.',
    help: 'https://github.com/abregoarthur-star/mcp-audit#what-it-checks',
  },
};

// mcp-audit severity → SARIF level
// SARIF levels: "none", "note", "warning", "error"
const SEVERITY_TO_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

// GitHub surfaces `error` findings as blocking, `warning` as informational,
// `note` as hint. This aligns with the severity weight mcp-audit rules assign.

function messageText(finding) {
  const parts = [finding.title];
  if (finding.description) parts.push(finding.description);
  if (finding.remediation) parts.push(`\n\n**Remediation:** ${finding.remediation}`);
  if (finding.references?.length) {
    parts.push('\n\n**References:**');
    for (const ref of finding.references) parts.push(`- ${ref}`);
  }
  return parts.join('\n');
}

function messageMarkdown(finding) {
  // Same content but with markdown formatting for GitHub's rich rendering
  let md = `**${finding.title}**\n\n${finding.description || ''}`;
  if (finding.target) {
    md += `\n\n*Target:* \`${finding.target.kind}/${finding.target.name}\``;
  }
  if (finding.evidence && Object.keys(finding.evidence).length > 0) {
    md += '\n\n*Evidence:*\n```json\n' + JSON.stringify(finding.evidence, null, 2) + '\n```';
  }
  if (finding.remediation) {
    md += `\n\n*Remediation:* ${finding.remediation}`;
  }
  return md;
}

function artifactLocation(report) {
  // SARIF wants a URI relative to the project root. For a manifest-based audit,
  // we cite the manifest path if we have it. For stdio/http scans, we use a
  // synthetic URI that identifies the target (which is what shows up in GitHub's
  // "Files changed" column on a PR).
  if (report.server.transport === 'manifest' && report.server.url) {
    return { uri: report.server.url, uriBaseId: '%SRCROOT%' };
  }
  if (report.server.url) {
    return { uri: report.server.url };
  }
  return { uri: `mcp-server/${report.server.name || 'unknown'}` };
}

function locationsFor(finding, report) {
  // GitHub code-scanning requires at least one physicalLocation per result.
  const artifact = artifactLocation(report);
  const logicalName = finding.target
    ? `${finding.target.kind}/${finding.target.name}`
    : (report.server.name || 'server');

  return [
    {
      physicalLocation: {
        artifactLocation: artifact,
        // We don't have source-map line info for AST-extracted manifests, so
        // we point at line 1. GitHub still groups findings correctly by
        // logicalLocation.
        region: { startLine: 1, startColumn: 1 },
      },
      logicalLocations: [
        {
          name: logicalName,
          kind: finding.target?.kind === 'tool' ? 'function' : 'type',
        },
      ],
    },
  ];
}

function partialFingerprint(finding) {
  // Stable identity for a finding across runs so GitHub can track
  // "is this the same finding I flagged last PR?" Combines ruleId +
  // target identity + a canonical evidence hash. Deliberately NOT including
  // the timestamp or any run-specific data.
  const keyParts = [
    finding.ruleId,
    finding.target?.kind || '',
    finding.target?.name || '',
    finding.evidence?.field || finding.evidence?.param || finding.evidence?.key || '',
  ];
  return { primaryLocationLineHash: keyParts.filter(Boolean).join('::') };
}

export function renderSarif(report) {
  const ruleIdToIndex = {};
  const rules = Object.entries(RULE_CATALOG).map(([id, spec], index) => {
    ruleIdToIndex[id] = index;
    return {
      id,
      name: spec.name,
      shortDescription: { text: spec.short },
      fullDescription: { text: spec.full },
      helpUri: spec.help,
      help: {
        text: spec.full,
        markdown: `${spec.full}\n\n[mcp-audit rule catalog →](${spec.help})`,
      },
      defaultConfiguration: { level: 'warning' },
    };
  });

  const results = (report.findings || []).map(f => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIdToIndex[f.ruleId] ?? 0,
    level: SEVERITY_TO_LEVEL[f.severity] || 'note',
    message: {
      text: messageText(f),
      markdown: messageMarkdown(f),
    },
    locations: locationsFor(f, report),
    partialFingerprints: partialFingerprint(f),
    properties: {
      'mcp-audit/severity': f.severity,
      'mcp-audit/target-kind': f.target?.kind || null,
      'mcp-audit/target-name': f.target?.name || null,
      tags: [
        'mcp',
        'ai-security',
        `severity-${f.severity}`,
        ...(f.target?.kind ? [`target-${f.target.kind}`] : []),
      ],
    },
  }));

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-audit',
            version: pkg.version,
            informationUri: 'https://github.com/abregoarthur-star/mcp-audit',
            organization: '@dj_abstract',
            semanticVersion: pkg.version,
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: report.auditedAt,
            properties: {
              'mcp-audit/server-name': report.server.name,
              'mcp-audit/server-version': report.server.version || null,
              'mcp-audit/server-transport': report.server.transport,
              'mcp-audit/tool-count': report.server.counts.tools,
              'mcp-audit/resource-count': report.server.counts.resources,
              'mcp-audit/prompt-count': report.server.counts.prompts,
              'mcp-audit/finding-count': report.summary.total,
              'mcp-audit/findings-by-severity': report.summary.bySeverity,
            },
          },
        ],
        results,
        // columnKind=utf16CodeUnits matches GitHub's expectation for code-scanning
        columnKind: 'utf16CodeUnits',
      },
    ],
  };
}
