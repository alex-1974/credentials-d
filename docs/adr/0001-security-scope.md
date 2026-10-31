# ADR 0001 — Security scope and library boundary

**Status:** Accepted for bootstrap  
**Date:** 2026-10-30

## Context

Applications need to retain small high-value credentials such as OAuth access
tokens and API keys without placing them in ordinary settings files.

The motivating consumer is Dunia, which may manage multiple OpenStreetMap
identities on one machine. A stored OSM `write_api` token can authorize
changes to a public production system, so credential handling is a real
security boundary rather than merely a preferences feature.

The problem is generic and not specific to OpenStreetMap or OAuth.

## Decision

`credentials-d` owns a small, application-independent credential-storage
domain.

It may provide:

- opaque credential handles;
- controlled secret lifetime;
- credential-store contracts;
- platform credential-store backends;
- an optional encrypted-vault backend if separately justified and qualified;
- test/memory backends needed to verify the common contract.

It does not own:

- OAuth flows;
- HTTP clients;
- OpenStreetMap identities;
- application user/profile management;
- authorization policy for application actions;
- password-manager functionality;
- general-purpose cryptographic APIs.

Cryptographic primitives will not be implemented in this repository. Any
encrypted-vault backend must depend on a separately qualified cryptographic
implementation and expose only the narrow functionality required by the vault.

## Security boundary

The library should protect against realistic application-level failures such
as:

- credentials written to ordinary settings or logs;
- accidental cross-profile credential use;
- leaked backup/configuration files;
- malformed or tampered vault data;
- stale credential records after explicit deletion where the backend can
  provide that guarantee.

It does not claim to protect secrets from an attacker who already controls the
operating system, root/administrator account, or the running process.

## Consequences

The public API must be intentionally small.

Backends must fail closed when a required security property is unavailable.

Differences between OS credential stores must be represented as capabilities
or documented backend contracts rather than silently weakened to a lowest
common denominator.

Security fixes and dependency updates are release-relevant work.
