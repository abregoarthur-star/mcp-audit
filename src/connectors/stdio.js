import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

export async function connectStdio(commandSpec, opts = {}) {
  const { command, args, env } = parseCommand(commandSpec);

  const transport = new StdioClientTransport({
    command,
    args,
    env: { ...process.env, ...(env || {}) },
    stderr: 'pipe',
  });

  const client = new Client(
    { name: 'mcp-audit', version: '0.1.0' },
    { capabilities: {} }
  );

  await client.connect(transport);

  try {
    return await snapshot(client, {
      transport: 'stdio',
      url: null,
      command: commandSpec,
      auth: { kind: 'process-trust' },
    });
  } finally {
    await client.close().catch(() => {});
    await transport.close?.().catch(() => {});
  }
}

function parseCommand(spec) {
  if (typeof spec === 'object' && spec.command) {
    return { command: spec.command, args: spec.args || [], env: spec.env };
  }
  // shell-style string. naive split that respects quoted args.
  const tokens = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(spec)) !== null) tokens.push(m[1] ?? m[2] ?? m[3]);
  if (!tokens.length) throw new Error('Empty stdio command');
  return { command: tokens[0], args: tokens.slice(1), env: undefined };
}

async function snapshot(client, meta) {
  const info = client.getServerVersion?.() || {};
  const capabilities = client.getServerCapabilities?.() || {};

  const tools = capabilities.tools ? await safeList(() => client.listTools()) : { tools: [] };
  const resources = capabilities.resources ? await safeList(() => client.listResources()) : { resources: [] };
  const prompts = capabilities.prompts ? await safeList(() => client.listPrompts()) : { prompts: [] };

  return {
    name: info.name || meta.command || meta.url || 'unknown',
    version: info.version || null,
    transport: meta.transport,
    url: meta.url,
    auth: meta.auth,
    capabilities,
    tools: tools.tools || [],
    resources: resources.resources || [],
    prompts: prompts.prompts || [],
  };
}

async function safeList(fn) {
  try { return await fn(); }
  catch (e) { return { error: e.message, tools: [], resources: [], prompts: [] }; }
}
