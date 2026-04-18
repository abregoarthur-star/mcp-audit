#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { audit } from '../src/index.js';
import { renderTerminal } from '../src/reporters/terminal.js';
import { renderHtml } from '../src/reporters/html.js';

const HELP = `mcp-audit — security auditor for MCP servers

Usage:
  mcp-audit scan --stdio "<command>"        Spawn a local MCP server over stdio and audit it
  mcp-audit scan --url <url>                Audit a remote MCP server (HTTP/SSE)
  mcp-audit scan --manifest <path.json>     Audit a static MCP manifest

Options:
  --bearer <token>            Bearer token for HTTP servers
  --header "<K: V>"           Extra header (repeatable)
  --json [path]               Emit JSON report (stdout if no path)
  --html <path>               Emit HTML report
  --quiet                     Suppress terminal report
  --fail-on <severity>        Exit non-zero if any finding >= severity (critical|high|medium|low)
  -h, --help                  Show this help

Examples:
  mcp-audit scan --stdio "node ./my-mcp-server.js"
  mcp-audit scan --url https://mcp.example.com --bearer $TOKEN --html report.html
  mcp-audit scan --manifest server.json --fail-on high
`;

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') {
    process.stdout.write(HELP);
    process.exit(0);
  }

  if (argv[0] !== 'scan') {
    process.stderr.write(`Unknown command: ${argv[0]}\n\n${HELP}`);
    process.exit(2);
  }

  const opts = parseArgs(argv.slice(1));
  if (opts.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const spec = {
    stdio: opts.stdio,
    url: opts.url,
    manifest: opts.manifest,
    bearer: opts.bearer,
    headers: opts.headers,
  };

  let report;
  try {
    report = await audit(spec);
  } catch (e) {
    process.stderr.write(`Audit failed: ${e.message}\n`);
    if (process.env.DEBUG) console.error(e);
    process.exit(2);
  }

  if (!opts.quiet) {
    process.stdout.write(renderTerminal(report));
  }

  if (opts.json !== undefined) {
    const json = JSON.stringify(report, null, 2);
    if (opts.json === true || opts.json === '') {
      process.stdout.write(json + '\n');
    } else {
      await writeFile(opts.json, json);
      process.stderr.write(`JSON report written: ${opts.json}\n`);
    }
  }

  if (opts.html) {
    await writeFile(opts.html, renderHtml(report));
    process.stderr.write(`HTML report written: ${opts.html}\n`);
  }

  if (opts.failOn) {
    const threshold = SEV_RANK[opts.failOn];
    if (threshold === undefined) {
      process.stderr.write(`Invalid --fail-on value: ${opts.failOn}\n`);
      process.exit(2);
    }
    const worst = report.findings.reduce((acc, f) => Math.max(acc, SEV_RANK[f.severity] ?? 0), 0);
    if (worst >= threshold) process.exit(1);
  }
}

function parseArgs(args) {
  const out = { headers: {} };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const next = () => args[++i];
    switch (a) {
      case '--stdio':    out.stdio = next(); break;
      case '--url':      out.url = next(); break;
      case '--manifest': out.manifest = next(); break;
      case '--bearer':   out.bearer = next(); break;
      case '--header': {
        const v = next();
        const idx = v.indexOf(':');
        if (idx > 0) out.headers[v.slice(0, idx).trim()] = v.slice(idx + 1).trim();
        break;
      }
      case '--json': {
        const peek = args[i + 1];
        out.json = (peek && !peek.startsWith('--')) ? next() : true;
        break;
      }
      case '--html':    out.html = next(); break;
      case '--quiet':   out.quiet = true; break;
      case '--fail-on': out.failOn = next(); break;
      case '-h':
      case '--help':    out.help = true; break;
      default:
        process.stderr.write(`Unknown arg: ${a}\n`);
        process.exit(2);
    }
  }
  return out;
}

main().catch(e => {
  process.stderr.write(`Fatal: ${e.message}\n`);
  if (process.env.DEBUG) console.error(e);
  process.exit(2);
});
