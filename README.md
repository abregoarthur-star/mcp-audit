# mcp-audit

[![npm version](https://img.shields.io/npm/v/@dj_abstract/mcp-audit.svg?color=cb3837&logo=npm)](https://www.npmjs.com/package/@dj_abstract/mcp-audit)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node.js >=20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org/)

A security auditor for **Model Context Protocol (MCP)** servers. Scans tool, resource, and prompt definitions for AI-native security issues — prompt injection, tool poisoning, dangerous capability combinations, schema permissiveness, and more.

> Why this exists: MCP servers ship arbitrary text directly into the host LLM's context. A malicious or sloppy server can manipulate any agent that connects to it. As the MCP ecosystem grows, the surface for prompt injection, tool poisoning, and "lethal trifecta" capability combinations grows with it. There's no shortage of CVE scanners. There's almost nothing focused on the threats that are unique to agent infrastructure.

## What it checks

| Rule | Severity (worst case) | What it catches |
|------|-----------------------|------------------|
| `prompt-injection` | critical | Instruction overrides, role redefinition, fake system tags, system-prompt extraction, silent-exfiltration directives, and other injection patterns embedded in tool/prompt/resource descriptions. |
| `invisible-instructions` | critical | Unicode Tag block characters (the "ASCII Smuggler" attack), zero-width characters, control characters, and large base64 blobs hidden in descriptions. |
| `tool-poisoning` | high | Hidden capabilities (params not mentioned in the description), read-only claims contradicted by mutating params, descriptions that reference a different tool name. |
| `unsafe-tool-combos` | critical | "Lethal trifecta" combinations on a single server: shell-exec + network-egress, file-read + network-egress, secret-read + network-egress, file-write + shell-exec. |
| `sensitive-output` | high | Tools whose names suggest they return secrets, env vars, credentials, sessions, or private keys. |
| `destructive-no-confirm` | medium | Destructive tools (`delete_*`, `drop_*`, `kill_*`) with no confirmation parameter. |
| `schema-permissiveness` | high | Unbounded string params on command-shaped surfaces, missing `inputSchema`, `additionalProperties: true`, undefined object structures. |
| `unauthenticated-server` | high | Remote (HTTP/SSE) MCP servers that accept connections without auth. |
| `excessive-scope` | medium | A single server spanning many unrelated capability domains (filesystem + network + shell + db + …) — large blast radius if compromised. |

## Install

One-shot with `npx` (no install):

```bash
npx @dj_abstract/mcp-audit scan --stdio "node ./my-mcp-server.js"
```

Global install:

```bash
npm install -g @dj_abstract/mcp-audit
mcp-audit --help
```

Or clone and run from source:

```bash
git clone https://github.com/abregoarthur-star/mcp-audit
cd mcp-audit
npm install
node bin/mcp-audit.js --help
```

Requires Node.js 20+.

## Usage

### Scan a local stdio MCP server

```bash
mcp-audit scan --stdio "node ./my-mcp-server.js"
```

### Scan a remote HTTP/SSE server

```bash
mcp-audit scan --url https://mcp.example.com/sse --bearer "$TOKEN"
mcp-audit scan --url https://mcp.example.com --header "X-Api-Key: $KEY"
```

### Scan a static manifest

Useful for offline audits, CI pipelines, or auditing in-process SDK servers (see "Auditing Agent SDK servers" below).

```bash
mcp-audit scan --manifest server.json
```

### Output formats

```bash
mcp-audit scan --stdio "..." --html report.html        # standalone HTML, share-friendly
mcp-audit scan --stdio "..." --json report.json        # JSON for CI / automation
mcp-audit scan --stdio "..." --json                    # JSON to stdout
mcp-audit scan --stdio "..." --quiet --json | jq ...   # piping
```

### CI gate

Exit non-zero if any finding meets a severity threshold:

```bash
mcp-audit scan --stdio "..." --fail-on high
```

## Auditing Agent SDK servers

Servers built with the Anthropic Agent SDK's `createSdkMcpServer()` run in-process; they are not standalone stdio servers. Use the bundled extractor to dump them as a manifest first:

```bash
node bin/extract-sdk-server.js path/to/your-mcp.js exportName /tmp/manifest.json
mcp-audit scan --manifest /tmp/manifest.json --html report.html
```

## Sample finding

```
 CRITICAL  Shell execution + network egress on same server
  rule: unsafe-tool-combos  ·  target: server/brain-tools
  A single server provides both arbitrary command execution and outbound
  network capability. Any prompt-injection that lands here can run a
  command and exfiltrate the output in one hop.
  evidence:
    shell_exec: ["execute_command"]
    network_out: ["create_linkedin_draft","security_intel","market_intel",
                  "send_telegram","manage_tasks","read_email","send_email"]
  remediation:
    Split capabilities across separate MCP servers with separate trust
    boundaries. The host agent can compose them, but a compromise of one
    server should not yield the full kill chain.
  refs:
    - https://owasp.org/www-project-top-10-for-large-language-model-applications/
    - https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
```

## Threat model

`mcp-audit` is a **static analyzer** of an MCP server's surface. It does not execute tools, send payloads, or attempt exploitation. Every check is read-only:

- For **stdio** servers: spawn the server, perform the MCP `initialize`/`tools/list`/`resources/list`/`prompts/list` handshakes, then close.
- For **HTTP/SSE** servers: connect, list, close.
- For **manifests**: pure file read.

This makes it safe to run against production servers, including third-party servers you don't own.

It will not catch:

- Vulnerabilities in tool **implementations** (e.g. SQL injection inside a `query_db` handler).
- Behavior that only manifests at call time (e.g. rate-limit issues, time-of-check / time-of-use bugs).
- Backdoored binaries or supply-chain compromise of the server itself.

Pair it with conventional SAST/DAST and supply-chain scanning.

## Programmatic API

```javascript
import { audit } from '@dj_abstract/mcp-audit';

const report = await audit({ stdio: 'node ./server.js' });
console.log(report.summary.bySeverity);
for (const f of report.findings) {
  console.log(f.severity, f.ruleId, f.title);
}
```

## Roadmap

- Detection-only Nuclei-style remote checks (auth bypass probes, CORS misconfig)
- Per-tool permission-cost scoring (rank which tools deserve human-in-the-loop gating)
- Differential audits (compare two manifests; flag rug-pulls and silent capability changes)
- Integration with the [MCP server registry](https://modelcontextprotocol.io/) for community scoring
- Recipe for Brain Agent SDK to call `audit()` before connecting to any new server

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Tool Poisoning Attacks (Invariant Labs)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [The Lethal Trifecta (Simon Willison)](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [Hiding and finding text with Unicode Tags (Embrace The Red)](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Model Context Protocol specification](https://modelcontextprotocol.io/)

## License

MIT — see [LICENSE](./LICENSE).
