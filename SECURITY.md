# Security policy

## Supported versions

Only the latest release (and `master`) receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/jean1880/nuvek-core/security/advisories/new),
not in a public issue. Only the maintainers see the report.

Include the version, the steps to reproduce and the impact you expect. Leave out real secrets,
tokens and hostnames: a placeholder shows the problem just as well.

You should get an acknowledgement within a week. Once a fix is released, the advisory is published
with credit to the reporter unless you prefer otherwise.

## Scope

nuvek-core is a library. Of particular interest:

- a secret that `scrub::redact`, `redact_config` or `Masker` lets through in a shape it claims to
  cover;
- a command that touches a built-in or configured secret surface but that `touches_secret_surface`
  does not flag, or a way to make `scrub::init` succeed while leaving configured surfaces out of
  force;
- a write query that gets past the read-only guard in `nuvek-neo4j`;
- the SSH runner prompting, hanging past its timeout, or running a command on a host the caller
  did not name.

Vulnerabilities in ChromaDB, Neo4j, Ollama or another dependency belong with that project.
