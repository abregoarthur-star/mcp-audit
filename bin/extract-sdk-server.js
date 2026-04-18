#!/usr/bin/env node
// Extract a static manifest from an Agent-SDK in-process MCP server.
// Usage:
//   node bin/extract-sdk-server.js <path-to-module> <export-name> [out.json]
//
// The target module must export an object created via createSdkMcpServer().
// We dump its registered tools/resources/prompts as a manifest the auditor consumes.

import { writeFile } from 'node:fs/promises';
import { resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , modPath, exportName = 'default', outPath] = process.argv;

if (!modPath) {
  console.error('Usage: extract-sdk-server.js <module-path> [exportName] [out.json]');
  process.exit(2);
}

const abs = isAbsolute(modPath) ? modPath : resolve(process.cwd(), modPath);
const mod = await import(pathToFileURL(abs).href);
const srv = mod[exportName] ?? mod.default;
if (!srv || !srv.instance) {
  console.error(`Export "${exportName}" is not an SDK MCP server.`);
  process.exit(2);
}

const inst = srv.instance;
const z = await tryImport('zod/v4');

function convertSchema(schema) {
  if (!schema) return null;
  if (z?.toJSONSchema) {
    try { return z.toJSONSchema(schema); } catch { /* fall through */ }
  }
  if (typeof schema === 'object' && schema.type) return schema;
  return null;
}

function entries(obj) { return obj ? Object.entries(obj) : []; }

const tools = entries(inst._registeredTools).map(([name, t]) => ({
  name,
  description: t.description || t.title || '',
  inputSchema: convertSchema(t.inputSchema),
}));

const resources = entries(inst._registeredResources).map(([uri, r]) => ({
  uri,
  name: r.name || uri,
  description: r.description || r.title || '',
  mimeType: r.mimeType || null,
}));

const prompts = entries(inst._registeredPrompts).map(([name, p]) => ({
  name,
  description: p.description || p.title || '',
  arguments: p.argsSchema ? Object.keys(p.argsSchema).map(n => ({ name: n })) : [],
}));

const manifest = {
  name: srv.name || abs,
  version: srv.version || null,
  transport: 'sdk-in-process',
  auth: { kind: 'process-trust' },
  tools,
  resources,
  prompts,
};

const json = JSON.stringify(manifest, null, 2);
if (outPath) {
  await writeFile(outPath, json);
  console.error(`Manifest written: ${outPath} (${tools.length} tools, ${resources.length} resources, ${prompts.length} prompts)`);
} else {
  process.stdout.write(json);
}

async function tryImport(name) {
  try { return await import(name); } catch { return null; }
}
