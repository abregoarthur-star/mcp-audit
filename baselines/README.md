# Baselines

Frozen audit reports under version control so future runs can be compared against a fixed reference point.

## Index

| File | Server | Date | Findings (C / H / M / L) |
|------|--------|------|--------------------------|
| `brain-tools-v1-2026-04-17.json` | DJ Abstract Brain — `brain-tools` MCP server (16 tools) | 2026-04-17 | 0 / 0 / 0 / 17 |
| `brain-exec-v1-2026-04-17.json` | DJ Abstract Brain — `brain-exec` MCP server (1 tool, isolated) | 2026-04-17 | 0 / 0 / 0 / 0 |

## Backstory

A pre-fix audit (not stored here — see `git log`) found:
- **CRITICAL** lethal trifecta on `brain-tools`: `execute_command` co-resident with 7 network-egress tools
- **HIGH** hidden capability: `send_email`'s `body` param undocumented
- **HIGH** unbounded query strings on `search_news`, `security_intel`, `read_email`
- **MEDIUM** missing input schema on `architect_command`

These were fixed in the [DJ Abstract AI Brain repo](https://github.com/abregoarthur-star/abstract-ai-brain) by:
1. Splitting `execute_command` to its own `brain-exec` MCP server (broke the trifecta)
2. Documenting the hidden param
3. Adding `maxLength`/`max` bounds to all string and number params
4. Fixing the Zod schema so it converts cleanly to JSON Schema

The post-fix audit (stored here) shows 0 / 0 / 0 across critical/high/medium severities.
