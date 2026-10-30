# ADR 0003 — Core security hardening before native backends

**Status:** Accepted for Issue #7 implementation  
**Date:** 2026-10-30

## Context

The first public API prototype deliberately separated secret plaintext from
persistable handles, but it still used a GC-managed class for `SecretBuffer`.

That representation was suitable for API qualification, not for production
security:

- D class finalization is GC-driven and not a deterministic resource-lifetime
  mechanism;
- a class finalizer must not rely on GC-managed subobjects still being valid;
- ordinary zero-filling can be removed by optimizing compilers when the memory
  is not observed afterwards;
- package-private byte duplication encouraged extra plaintext copies;
- handles were not yet bound to a consumer namespace or store instance;
- capability booleans were too vague to support honest platform backends.

Native OS backends must not be built on those assumptions.

## Decision

### SecretBuffer becomes a non-copyable value type

`SecretBuffer` is a struct that owns one `malloc` allocation.

Copy construction is disabled:

```d
@disable this(this);
```

D move semantics may transfer ownership without duplicating the allocation.

The destructor clears and frees only non-GC state. Consumers can call
`clear()` earlier for prompt cleanup.

### Zeroization uses core.volatile

Owned secret memory is overwritten byte-for-byte through
`core.volatile.volatileStore`.

These stores are compiler-recognized volatile operations and are not removable
as dead assignments.

This guarantee applies only to the allocation owned by `SecretBuffer`.
credentials-d cannot erase:

- the caller's source buffer;
- copies deliberately made inside an explicit plaintext callback;
- register or stack spills outside its control;
- OS swap, hibernation or memory capture;
- memory visible to a compromised process.

### No production secret duplication helper

`SecretBuffer.duplicateBytes` is removed.

A backend that must copy plaintext must do so explicitly at its own trust
boundary and own the resulting lifetime. Production OS backends should prefer
passing the scoped plaintext view directly to the native API.

The in-memory reference backend remains intentionally non-production and may
copy into GC storage for contract testing.

### CredentialNamespace

Every store instance is bound to one validated, non-secret application
namespace.

Canonical lowercase reverse-DNS-style names are recommended.

The namespace is a routing/isolation mechanism, not an authorization identity.

### Store-bound handles

Backends control the complete serialized handle.

The memory backend includes a unique store-instance component so a handle from
one store cannot accidentally resolve to a same-numbered record in another
store.

Persistent production stores will use stable backend-specific record
locators, generated from a cryptographically strong source where uniqueness is
security-relevant.

### Explicit status taxonomy

Normal backend outcomes distinguish:

- missing record;
- locked state;
- interaction required;
- user cancellation;
- backend unavailable;
- permission denial;
- unsupported operation;
- size violation;
- ambiguous lookup;
- corrupt data;
- invalid input;
- generic backend failure.

Errors remain non-secret.

### Explicit capabilities

The common contract describes concrete properties instead of broad claims such
as `hardwareBacked`.

Capabilities now describe:

- persistence;
- at-rest protection model;
- unlock model;
- user-presence support;
- mobility/synchronization;
- logical deletion confirmation;
- blocking/prompt behavior;
- concurrency contract.

A backend must report only properties it can actually establish.

### No silent fallback

credentials-d does not define a fallback chain.

If the selected store is unavailable, it reports `unavailable`. It must not
silently:

- write plaintext settings;
- create an ad-hoc file;
- switch to a weaker credential store;
- switch to an encrypted vault not explicitly selected by the consumer.

Backend choice is a consumer security decision.

## Consequences

The pre-0.1 API changes from reference-semantics secrets:

```d
auto secret = new SecretBuffer(bytes);
```

to value-semantics ownership:

```d
auto secret = SecretBuffer(bytes);
```

Store input parameters become scoped const references.

The memory backend requires an explicit `CredentialNamespace`.

The implementation remains dependency-free at the semantic core. libsodium or
another native dependency is not required merely to guarantee zeroization.

A future secure-memory backend may add page locking, dump exclusion or guarded
allocations, but such features must be separately qualified and capability
documented. They do not weaken this baseline.

## Regression requirements

- `SecretBuffer` copy attempts fail to compile;
- implicit conversion to `string` fails to compile;
- plaintext view escape fails under DIP1000;
- common formatting attempts fail to compile;
- volatile zeroization is unit-tested;
- cross-store handles fail closed;
- forced `unavailable` does not produce a handle;
- the same contracts run under DMD and LDC and in the release compiler matrix.
