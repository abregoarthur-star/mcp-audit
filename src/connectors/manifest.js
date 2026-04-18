import { readFile } from 'node:fs/promises';

// Load a static MCP server manifest from a JSON file.
// Useful for offline audits, CI gates, and snapshotting servers without re-spawning them.
//
// Expected shape (loose — we accept either flat or nested):
//   {
//     name, version, transport?, url?,
//     auth?: { kind, required },
//     capabilities?: {},
//     tools: [{ name, description, inputSchema }],
//     resources: [{ uri, name, description, mimeType }],
//     prompts: [{ name, description, arguments }]
//   }

export async function loadManifest(path) {
  const raw = await readFile(path, 'utf8');
  const parsed = JSON.parse(raw);

  return {
    name: parsed.name || path,
    version: parsed.version || null,
    transport: parsed.transport || 'manifest',
    url: parsed.url || null,
    auth: parsed.auth || { kind: 'unknown' },
    capabilities: parsed.capabilities || {},
    tools: parsed.tools || [],
    resources: parsed.resources || [],
    prompts: parsed.prompts || [],
  };
}
