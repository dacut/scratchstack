# scratchstack-core

Core types shared across the Scratchstack libraries and services.

This crate holds the pieces that every Scratchstack service needs and that none of them should
define twice: the error model, request ids, the AWS query protocol in both directions, response
envelopes, and the logging macros for records that carry request material.

## Modules

| Module | Contents |
|---|---|
| `error` | `ErrorType` (sender vs. receiver), the `GenericError` type, and the `ProvideErrorMetadata` trait that lets any error report its code, message, HTTP status, and request id |
| `request_id` | `RequestId` — a UUIDv7 carrying the time the request arrived |
| `query` | Deserialization of AWS query-protocol request parameters, via `from_query_str` |
| `xml` | Serialization of values as the query protocol's response XML |
| `response` | Response envelopes and Axum response construction — behind the `axum` feature |
| `tls` | `TlsListener`, for serving over TLS — behind the `tls` feature |
| `macros` | The `sensitive_log` family, described below |

The crate also re-exports the `http` crate it is built against, as `scratchstack_core::http`, so
dependents cannot accidentally link a second, incompatible copy.

## Request ids

`RequestId` is a UUIDv7, so a request id sorts by, and carries, the time the request arrived —
which makes it directly useful for finding the request in a log rather than merely correlating
lines. The timestamp has microsecond resolution:

| Bits | 0–47 | 48–51 | 52–63 | 64–65 | 66–127 |
|---|---|---|---|---|---|
| | Timestamp (ms) | Version (`0111`) | Microseconds | Variant (`10`) | Random |

The whole-millisecond part occupies the first 48 bits and the remaining 0–999 microseconds share
the next 16 with the version nibble; `RequestId::microseconds` recombines them. Timestamps before
the Unix epoch are not representable — the layout has no sign bit.

## Sensitive logging

Tracing an authentication or authorization decision means logging what the decision was made from:
credentials, canonical requests, policy documents, principals, resources, and session data. That is
exactly what a log aggregator should never see. The `sensitive_log`, `sensitive_trace`,
`sensitive_debug`, `sensitive_info`, `sensitive_warn`, and `sensitive_error` macros compile to
nothing unless sensitive logging is switched on.

**The gate is not a feature of this crate**, and that is deliberate. Cargo unifies features across
the dependency graph, so a `sensitive-logging` feature here would mean that switching it on for one
crate switched on every other crate's records too. Instead the macros test
`cfg!(feature = "sensitive-logging")` *inside the macro body*, which is evaluated where the macro
expands — so each crate declares its own `sensitive-logging` feature and enabling it exposes that
crate's records and no other's. See
[`scratchstack-aws-signature`](../scratchstack-aws-signature) and
[`scratchstack-aspen`](../scratchstack-aspen), which each declare one.

Records that carry no request material — internal invariant violations, serializer failures — use
the `log` macros directly and are always compiled in.

## Features

| Feature | Default | Effect |
|---|---|---|
| `axum` | yes | The `response` module, and the `quick-xml` serializer that `xml` wraps |
| `tls` | no | The `tls` module |
| `form`, `http1`, `http2`, `macros`, `original-uri`, `query`, `tokio`, `tower-log`, `tracing` | no | Forward to the Axum features of the same name |

Note that the `macros` feature forwards to Axum and is unrelated to this crate's `macros` module,
which is always available.

## Documentation

Published to [docs.rs](https://docs.rs/scratchstack-core/).
