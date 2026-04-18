// Destructive tools (delete, drop, kill, etc.) that don't require an explicit confirm parameter.

const DESTRUCTIVE_VERBS = /^(delete|remove|drop|destroy|purge|wipe|kill|terminate|reset|truncate|uninstall)/i;
const CONFIRM_PARAM = /^(confirm|confirmed|i_understand|force|really|yes_im_sure)$/i;

export const destructiveNoConfirm = {
  id: 'destructive-no-confirm',
  scope: 'item',
  check(target) {
    if (target.kind !== 'tool') return [];
    const tool = target.tool;
    if (!DESTRUCTIVE_VERBS.test(tool.name)) return [];

    const props = tool.inputSchema?.properties || {};
    const hasConfirm = Object.keys(props).some(p => CONFIRM_PARAM.test(p));

    if (!hasConfirm) {
      return [{
        ruleId: 'destructive-no-confirm',
        severity: 'medium',
        title: `Destructive tool "${tool.name}" has no explicit confirmation parameter`,
        description:
          'The tool name implies a destructive action, but its schema does not require any explicit ' +
          'confirmation flag. An LLM that gets prompt-injected can call it with valid-looking arguments. ' +
          'Even with host-side approval UIs, a "confirm: true" param adds a second, schema-enforced gate.',
        evidence: { name: tool.name, params: Object.keys(props) },
        target: { kind: 'tool', name: tool.name },
        remediation:
          'Add a required boolean confirmation parameter (e.g. "confirm" or "i_understand") that the model ' +
          'must explicitly set, and reject calls where it is not true. Combine with host-level approval UI.',
        references: [],
      }];
    }
    return [];
  },
};
