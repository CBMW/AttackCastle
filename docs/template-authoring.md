# Findings Template Authoring

Templates live under:

`src/attackcastle/findings/templates/`

Each template is JSON and must validate against the built-in schema.

Required sections:

- metadata: `id`, `version`, `title`, `severity`, `category`
- narrative: `description`, `impact`, `likelihood`
- remediation: `recommendations`, `references`
- taxonomy: `tags`, `plextrac`
- trigger logic: `trigger.entity_type`, `trigger.logic`, `trigger.conditions`
- evidence gates: `evidence_requirements`

Optional sections:

- `extends`: inherit from another template id
- `abstract`: mark template as non-instantiable (use for base templates)

Trigger operators currently supported:

- `exists`, `eq`, `neq`, `in`, `contains`, `contains_any`
- `regex`, `gt`, `gte`, `lt`, `lte`, `length_gte`

Suppression support:

- Provide a suppression file path via config (`findings.suppression_file`)
- Match fields: `template_id`, `entity_type`, `entity_id`, optional `expires_at`, `reason`
