# Security Policy

`credentials-d` is security-sensitive software.

## Reporting a vulnerability

Do not open a public issue for a previously undisclosed vulnerability that
could expose credentials, bypass a security boundary, weaken vault integrity,
or enable unsafe credential reuse.

Use GitHub's private vulnerability reporting for this repository when
available. If that channel is unavailable, contact the repository maintainer
privately before public disclosure.

Public issues are appropriate for hardening proposals that do not disclose an
exploitable condition.

## Scope

Security-sensitive areas include:

- secret lifetime and copying;
- platform credential-store adapters;
- encrypted-vault parsing and persistence;
- cryptographic-backend integration;
- credential deletion and replacement;
- logging, diagnostics and error handling involving secrets;
- dependency vulnerabilities that affect reachable credential operations.

A security fix is not complete until regression protection and required
documentation are in place.
