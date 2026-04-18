// For HTTP/SSE-transport MCP servers, flag missing/weak auth signals.
// We can only check what the connector observed (transport, response headers, auth challenges).

export const unauthenticatedServer = {
  id: 'unauthenticated-server',
  scope: 'server',
  check(target) {
    const server = target.server;
    const findings = [];

    if (server.transport === 'stdio') return [];

    if (!server.auth || server.auth.kind === 'none') {
      findings.push({
        ruleId: 'unauthenticated-server',
        severity: 'high',
        title: `MCP server "${server.name || server.url || 'unknown'}" appears to accept unauthenticated connections`,
        description:
          'Remote (HTTP/SSE) MCP servers should require authentication. Without auth, anyone who can ' +
          'reach the URL can enumerate tools and invoke them. Combined with any of the data-egress ' +
          'tools, this is an open data path.',
        evidence: { transport: server.transport, auth: server.auth || null, url: server.url || null },
        target: { kind: 'server', name: server.name || 'unknown' },
        remediation:
          'Require an Authorization header (bearer token or OAuth) and validate scopes per tool. Bind ' +
          'tokens to specific clients/users rather than a shared secret.',
        references: [
          'https://modelcontextprotocol.io/specification/server-developers',
        ],
      });
    }

    return findings;
  },
};
