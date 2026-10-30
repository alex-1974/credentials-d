# Contributing

`credentials-d` follows the engineering practices of the
`d-geospatial-workspace`.

Read `AGENTS.md` and the available `.workspace/` documents before making
architectural, API, lifetime, security, dependency, CI or release changes.

## Security-sensitive changes

Changes involving secret representation, persistence, credential-store
backends, cryptographic dependencies, vault formats, logging or deletion
semantics require:

- an explicit security rationale;
- tests for the intended condition and relevant failure cases;
- no silent weakening of an existing contract;
- documentation of compatibility or migration consequences.

Do not introduce a new cryptographic primitive implementation.

Undisclosed vulnerabilities must follow `SECURITY.md`, not a public issue.

## Branches

Normal integration targets `develop`. `main` is reserved for qualified
release state.
