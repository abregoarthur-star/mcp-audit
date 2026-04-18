// Detect overly permissive input schemas that give the LLM (or attacker) too much room.

function getRequired(schema) {
  return Array.isArray(schema?.required) ? new Set(schema.required) : new Set();
}

function evaluateProperty(name, def) {
  const issues = [];
  const type = def?.type;

  if (type === 'string') {
    const looksLikeCommand = /^(cmd|command|exec|shell|run|query|sql|code|script|filter|expression)$/i.test(name);
    const hasConstraints = def.enum || def.format || def.pattern || def.maxLength;
    if (!hasConstraints) {
      if (looksLikeCommand) {
        issues.push({
          severity: 'high',
          msg: `String param "${name}" has no enum/pattern/maxLength but its name suggests a command/query — unbounded input on a sensitive surface.`,
        });
      } else {
        issues.push({
          severity: 'low',
          msg: `String param "${name}" has no length, format, or pattern constraint.`,
        });
      }
    }
  }

  if (def?.additionalProperties === true) {
    issues.push({
      severity: 'medium',
      msg: `Object param "${name}" allows additionalProperties: true — accepts any extra keys.`,
    });
  }

  if (Array.isArray(def?.type)) {
    issues.push({
      severity: 'low',
      msg: `Param "${name}" has multiple types (${def.type.join('|')}) — broader input surface than necessary.`,
    });
  }

  if (def?.type === 'object' && !def.properties && !def.additionalProperties) {
    issues.push({
      severity: 'medium',
      msg: `Object param "${name}" has no defined properties and no additionalProperties constraint — completely unstructured.`,
    });
  }

  return issues;
}

export const schemaPermissiveness = {
  id: 'schema-permissiveness',
  scope: 'item',
  check(target) {
    if (target.kind !== 'tool') return [];
    const tool = target.tool;
    const schema = tool.inputSchema;
    if (!schema) {
      return [{
        ruleId: 'schema-permissiveness',
        severity: 'medium',
        title: `Tool "${tool.name}" has no input schema`,
        description:
          'No declared input schema. The host has no way to validate or constrain arguments the model passes.',
        evidence: {},
        target: { kind: 'tool', name: tool.name },
        remediation: 'Declare an inputSchema (JSON Schema) describing every parameter, including type, constraints, and required fields.',
        references: [],
      }];
    }

    const findings = [];
    const required = getRequired(schema);
    const props = schema.properties || {};

    for (const [name, def] of Object.entries(props)) {
      for (const issue of evaluateProperty(name, def)) {
        findings.push({
          ruleId: 'schema-permissiveness',
          severity: issue.severity,
          title: `Schema issue in tool "${tool.name}": ${issue.msg}`,
          description: issue.msg,
          evidence: { param: name, required: required.has(name), schema: def },
          target: { kind: 'tool', name: tool.name },
          remediation: 'Add appropriate constraints: enum for known sets, pattern/format for structured strings, maxLength bounds, properties for objects.',
          references: ['https://json-schema.org/'],
        });
      }
    }

    return findings;
  },
};
