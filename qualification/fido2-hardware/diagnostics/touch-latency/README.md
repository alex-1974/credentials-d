# FIDO2 touch-latency diagnostic

Standalone libfido2 diagnostic for physical touch-response latency.

It bypasses the credentials-d FIDO2 wrapper, vault, envelopes, and qualification
harness. It performs one non-resident MakeCredential with hmac-secret enabled,
then one GetAssertion with hmac-secret and user presence required.

Run:

```sh
cd qualification/fido2-hardware/diagnostics/touch-latency
DC=dmd dub run
```

If more than one FIDO device is visible:

```sh
DC=dmd dub run -- --device /dev/hidrawN
```

For each ACTION line, wait for the authenticator to blink and touch once.
The program reports monotonic wall-clock time around the blocking libfido2 calls:

```text
TIMING make_credential_ms=...
TIMING get_assertion_hmac_secret_ms=...
```

These timings include the human wait before touch. They are diagnostic values,
not performance benchmarks. The PIN is entered with terminal echo disabled and
the temporary native buffer is wiped before release.
