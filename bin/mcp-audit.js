#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { audit } from '../src/index.js';
import { diff } from '../src/diff.js';
import { renderTerminal } from '../src/reporters/terminal.js';
import { renderHtml } from '../src/reporters/html.js';
import { renderSarif } from '../src/reporters/sarif.js';
import { renderDiffTerminal } from '../src/reporters/diff-terminal.js';

const HELP = `mcp-audit — security auditor for MCP servers

Usage:
  mcp-audit scan --stdio "<command>"           Spawn a local MCP server over stdio and audit it
  mcp-audit scan --url <url>                   Audit a remote MCP server (HTTP/SSE)
  mcp-audit scan --manifest <path.json>        Audit a static MCP manifest
  mcp-audit diff <baseline.json> <current.json>  Compare two manifests; flag rug-pulls and drift

Scan options:
  --bearer <token>            Bearer token for HTTP servers
  --header "<K: V>"           Extra header (repeatable)
  --json [path]               Emit JSON report (stdout if no path)
  --html <path>               Emit HTML report
  --sarif <path>              Emit SARIF 2.1.0 report (GitHub code-scanning compatible)
  --quiet                     Suppress terminal report
  --fail-on <severity>        Exit non-zero if any finding >= severity (critical|high|medium|low)

Diff options:
  --json [path]               Emit JSON diff report (stdout if no path)
  --quiet                     Suppress terminal report
  --fail-on <severity>        Exit non-zero if any diff finding >= severity

  -h, --help                  Show this help

Examples:
  mcp-audit scan --stdio "node ./my-mcp-server.js"
  mcp-audit scan --url https://mcp.example.com --bearer $TOKEN --html report.html
  mcp-audit scan --manifest server.json --fail-on high
  mcp-audit scan --manifest server.json --sarif results.sarif  # for GitHub code-scanning
  mcp-audit diff baseline.json current.json --fail-on high
`;

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const cmd = argv[0];
  if (cmd === 'scan') return runScan(argv.slice(1));
  if (cmd === 'diff') return runDiff(argv.slice(1));

  process.stderr.write(`Unknown command: ${cmd}\n\n${HELP}`);
  process.exit(2);
}

async function runScan(args) {
  const opts = parseArgs(args);
  if (opts.help) { process.stdout.write(HELP); process.exit(0); }

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

  if (!opts.quiet) process.stdout.write(renderTerminal(report));

  if (opts.json !== undefined) {
    const json = JSON.stringify(report, null, 2);
    if (opts.json === true || opts.json === '') process.stdout.write(json + '\n');
    else {
      await writeFile(opts.json, json);
      process.stderr.write(`JSON report written: ${opts.json}\n`);
    }
  }

  if (opts.html) {
    await writeFile(opts.html, renderHtml(report));
    process.stderr.write(`HTML report written: ${opts.html}\n`);
  }

  if (opts.sarif) {
    await writeFile(opts.sarif, JSON.stringify(renderSarif(report), null, 2));
    process.stderr.write(`SARIF report written: ${opts.sarif}\n`);
  }

  applyFailOn(opts, report.findings);
}

async function runDiff(args) {
  // Positional args: baseline, current
  const positional = [];
  const flags = [];
  for (const a of args) (a.startsWith('--') || a.startsWith('-') ? flags : positional).push(a);

  // Some flag values follow the flag; re-parse properly
  const opts = parseArgs(args);
  if (opts.help) { process.stdout.write(HELP); process.exit(0); }

  const [baselinePath, currentPath] = opts._;
  if (!baselinePath || !currentPath) {
    process.stderr.write(`diff requires two positional args: <baseline.json> <current.json>\n\n${HELP}`);
    process.exit(2);
  }

  let result;
  try {
    result = await diff(baselinePath, currentPath);
  } catch (e) {
    process.stderr.write(`Diff failed: ${e.message}\n`);
    if (process.env.DEBUG) console.error(e);
    process.exit(2);
  }

  if (!opts.quiet) process.stdout.write(renderDiffTerminal(result));

  if (opts.json !== undefined) {
    const json = JSON.stringify(result, null, 2);
    if (opts.json === true || opts.json === '') process.stdout.write(json + '\n');
    else {
      await writeFile(opts.json, json);
      process.stderr.write(`JSON diff written: ${opts.json}\n`);
    }
  }

  applyFailOn(opts, result.findings);
}

function applyFailOn(opts, findings) {
  if (!opts.failOn) return;
  const threshold = SEV_RANK[opts.failOn];
  if (threshold === undefined) {
    process.stderr.write(`Invalid --fail-on value: ${opts.failOn}\n`);
    process.exit(2);
  }
  const worst = findings.reduce((acc, f) => Math.max(acc, SEV_RANK[f.severity] ?? 0), 0);
  if (worst >= threshold) process.exit(1);
}

function parseArgs(args) {
  const out = { headers: {}, _: [] };
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
      case '--sarif':   out.sarif = next(); break;
      case '--quiet':   out.quiet = true; break;
      case '--fail-on': out.failOn = next(); break;
      case '-h':
      case '--help':    out.help = true; break;
      default:
        if (a.startsWith('--')) {
          process.stderr.write(`Unknown arg: ${a}\n`);
          process.exit(2);
        }
        out._.push(a);
    }
  }
  return out;
}

main().catch(e => {
  process.stderr.write(`Fatal: ${e.message}\n`);
  if (process.env.DEBUG) console.error(e);
  process.exit(2);
});
