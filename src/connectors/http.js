import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

export async function connectHttp(url, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.bearer) headers.Authorization = `Bearer ${opts.bearer}`;

  // Probe whether auth is required (informational; we still try the requested headers).
  const auth = await probeAuth(url, headers);

  const requestInit = { headers };
  let transport;
  let transportLabel = 'http';

  // Prefer Streamable HTTP, fall back to SSE.
  try {
    transport = new StreamableHTTPClientTransport(new URL(url), { requestInit });
    const client = await tryConnect(transport);
    return await snapshot(client, { transport: transportLabel, url, auth });
  } catch (e) {
    transportLabel = 'sse';
    transport = new SSEClientTransport(new URL(url), { requestInit });
    const client = await tryConnect(transport);
    return await snapshot(client, { transport: transportLabel, url, auth });
  }
}

async function tryConnect(transport) {
  const client = new Client(
    { name: 'mcp-audit', version: '0.1.0' },
    { capabilities: {} }
  );
  await client.connect(transport);
  return client;
}

async function probeAuth(url, headers) {
  try {
    const res = await fetch(url, { method: 'GET', headers });
    if (res.status === 401 || res.status === 403) {
      const wwwAuth = res.headers.get('www-authenticate') || '';
      return { kind: wwwAuth.toLowerCase().startsWith('bearer') ? 'bearer' : 'unknown', required: true, status: res.status };
    }
    if (res.status >= 200 && res.status < 500) {
      const wwwAuth = res.headers.get('www-authenticate');
      return { kind: wwwAuth ? 'challenge' : 'none', required: !!wwwAuth, status: res.status };
    }
    return { kind: 'unknown', required: false, status: res.status };
  } catch (e) {
    return { kind: 'unreachable', required: false, error: e.message };
  }
}

async function snapshot(client, meta) {
  const info = client.getServerVersion?.() || {};
  const capabilities = client.getServerCapabilities?.() || {};

  const tools = capabilities.tools ? await safeList(() => client.listTools()) : { tools: [] };
  const resources = capabilities.resources ? await safeList(() => client.listResources()) : { resources: [] };
  const prompts = capabilities.prompts ? await safeList(() => client.listPrompts()) : { prompts: [] };

  await client.close().catch(() => {});

  return {
    name: info.name || meta.url || 'unknown',
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
