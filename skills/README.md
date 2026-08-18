# Future Dracula Skills

This directory documents a planned provider-neutral Skills architecture. It is
not an implemented runtime and contains no model weights or executable AI
component.

Skills are intended to capture operational knowledge such as:

- how Dracula project workflows fit together;
- when to use a particular application service or MCP tool;
- how to interpret `STATIC`, `RESOLVED`, `LIVE-READ VERIFIED`, `Observed`,
  `Inferred`, and `Suspected` evidence;
- decision procedures for choosing static, live, emulated, or QEMU analysis;
- bounded analysis playbooks; and
- safe artifact and report handling.

The goal is to reduce trial and error and unnecessary client context. Skills
supplement model knowledge; they do not increase a model's fundamental
intelligence.

Repository authoring sources are planned under `skills/`. Release packaging is
intended to install approved skills under:

```text
<install>\brain\skills\
```

No provider-specific skill package should be presented as a built-in Dracula
capability until a runtime, schema, tests, and security boundary are designed.
