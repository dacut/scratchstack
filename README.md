# Scratchstack

![Rust](https://github.com/dacut/scratchstack/workflows/Rust/badge.svg)

AWS-compatible IAM and STS services, and the Rust libraries they are built from.

Scratchstack implements the AWS identity APIs — SigV4 request signing verification, the IAM policy
language, and the IAM and STS wire protocols — against your own credential store rather than
Amazon's. If you run an ecosystem of AWS-like credentials, are building mock-AWS services, or want
AWS-shaped authentication and authorization somewhere AWS is not, this may be what you want.

**If you are trying to verify requests signed with AWS-vended credentials, this will not work for
you**, and no amount of configuration will change that. Verification needs the caller's secret key
or a derivative of it, and AWS does not hand those out. Use
[API Gateway with IAM authentication](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
instead. Likewise, if you only need to *sign* outgoing requests to real AWS services, you want the
[AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust) or, for signing alone,
[aws-sigv4](https://docs.rs/aws-sigv4/) — not this.

Several crates here are useful entirely on their own, whether or not you run the server.
[`scratchstack-aws-signature`](scratchstack-aws-signature) is the one most consumers use: it does
SigV4 verification and nothing else, and it has no opinion about where your credentials live.

## Status

Pre-1.0, and the API still moves between minor versions. Version 0.12 is current; upgrading from an
earlier release is covered by the migration guides:

* [0.11 → 0.12](scratchstack-aws-signature/src/migration/migration_0_11.rs)
* [0.10 → 0.12](scratchstack-aws-signature/src/migration/migration_0_10.rs)

At the service layer, IAM dispatches 69 operations and STS dispatches `AssumeRole` and
`GetCallerIdentity`. The database layer tracks the full AWS surface as a checklist —
70 of 176 IAM APIs, plus nine Scratchstack extensions with no AWS counterpart — in
[the `scratchstack-iam-database` README](scratchstack-iam-database/README.md).

## Crates

### Services and server

| Crate | What it does |
|---|---|
| [`scratchstack`](scratchstack) | The server binary. Runs every service it was built with from one process, driven by one config file; each service gets its own port, and services sharing a database share a connection pool. The `iam` and `sts` features select which are compiled in. |
| [`scratchstack-service-iam`](scratchstack-service-iam) | The IAM service: operation handlers, request dispatch, and the authorization checks each operation runs. |
| [`scratchstack-service-sts`](scratchstack-service-sts) | The STS service: `AssumeRole` and `GetCallerIdentity`. |
| [`scratchstack-service-common`](scratchstack-service-common) | What does not vary between services — shared constants and the AWS query-protocol helpers every dispatcher runs before handing off to an operation. |
| [`scratchstack-config`](scratchstack-config) | The configuration schema: database settings, HTTP listeners and TLS, runtime and scope options. |
| [`scratchstack-bootstrap`](scratchstack-bootstrap) | The `ssbs` binary: runs migrations and creates the initial partition, account, users, groups, roles, policies, and session-token encryption keys for a fresh database. See [its README](scratchstack-bootstrap/README.md). |

### Standalone libraries

These have no dependency on the server and are useful on their own.

| Crate | What it does |
|---|---|
| [`scratchstack-aws-signature`](scratchstack-aws-signature) | AWS SigV4 signature **verification**. Validates a signed `http::Request` against a signing key your own service supplies, with support for presigned URLs, S3 rules, streaming and `aws-chunked` bodies, session tokens, and an Axum middleware layer. See [its README](scratchstack-aws-signature/README.md). |
| [`scratchstack-aspen`](scratchstack-aspen) | The IAM policy language. Parses a policy document into a typed representation, serializes it back, and evaluates a request against a policy set — allows, explicit denies, permissions boundaries, condition operators, and policy variables. See [its README](scratchstack-aspen/README.md). |
| [`scratchstack-aws-principal`](scratchstack-aws-principal) | Actor principals — the exact, wildcard-free principals a service authenticates a request as — and the session data behind policy variables such as `aws:userid`. See [its README](scratchstack-aws-principal/README.md). |
| [`scratchstack-arn`](scratchstack-arn) | ARN parsing and construction, with per-component validators. The `iam` feature adds `IamResourceArn`, which splits an IAM ARN's resource into type, path, and name. See [its README](scratchstack-arn/README.md). |

### Supporting libraries

| Crate | What it does |
|---|---|
| [`scratchstack-core`](scratchstack-core) | Types shared across everything else: the error traits, `RequestId` (a UUIDv7 carrying request arrival time), AWS query-protocol deserialization, XML response serialization, and response envelopes. See [its README](scratchstack-core/README.md). |
| [`scratchstack-iam-database`](scratchstack-iam-database) | The PostgreSQL schema, its [migrations](scratchstack-iam-database/migrations), and the typed API each IAM and STS operation runs against it. |
| [`scratchstack-pagination`](scratchstack-pagination) | Tamper-resistant pagination tokens, encrypted with AES256-GCM under service-supplied keys that can be rotated. |
| [`scratchstack-cli-utils`](scratchstack-cli-utils) | Argument-parsing helpers for the command-line tools: list parsing and AWS-style shorthand syntax. |

### Code generation

| Crate | What it does |
|---|---|
| [`scratchstack-shapegen`](scratchstack-shapegen) | Generates *server-side* Rust from [Smithy](https://smithy.io/) models — the request, response, error, and action types a service implementation needs, where the AWS generators emit client types. Used only from `build.rs`. See [its README](scratchstack-shapegen/README.md). |
| [`scratchstack-shapes-iam`](scratchstack-shapes-iam) | The IAM API shapes, generated at build time from the bundled IAM Smithy model. |
| [`scratchstack-shapes-sts`](scratchstack-shapes-sts) | The STS API shapes, generated the same way. |
| [`scratchstack-shapegen-conformance`](scratchstack-shapegen-conformance) | Compiles shapegen's output for every Smithy shape kind, including the unions and `intEnum`s the real models never exercise. Not published; it exists so generator bugs fail the build instead of hiding. |

### Build support

| Crate | What it does |
|---|---|
| [`scratchstack-hakari`](scratchstack-hakari) | A [`cargo hakari`](https://docs.rs/cargo-hakari/) workspace-hack package. Unifies dependency features across the workspace so a crate is not rebuilt with different feature sets. Generated — do not edit by hand. |

## Building

The workspace requires a **nightly** toolchain, pinned by [`rust-toolchain.toml`](rust-toolchain.toml),
so rustup installs it on first use and a fresh checkout just works:

```sh
cargo build
cargo test
```

Nightly is needed because every crate carries `#![cfg_attr(doc, feature(doc_cfg))]` for the
"available on crate feature X" tags in the docs. rustdoc sets `cfg(doc)` for `cargo test --doc` as
well as `cargo doc`, so on stable both fail outright rather than merely dropping the tags.
`cargo +stable build` and `cargo +stable test --lib` still work if you ask for them explicitly.

Tests spin up an **embedded PostgreSQL** instance rather than talking to an external database, so
the suite needs no network access and no local server. That makes the database-backed tests closer
to integration tests than unit tests; they live in
[`scratchstack-iam-database/tests/iam_database.rs`](scratchstack-iam-database/tests/iam_database.rs)
and [`scratchstack-bootstrap/src/tests.rs`](scratchstack-bootstrap/src/tests.rs).

CI runs formatting, clippy, tests, and the doc build — see
[`.github/workflows/rust.yml`](.github/workflows/rust.yml).

## Running

Point [`ssbs`](scratchstack-bootstrap) at a PostgreSQL database to apply migrations and create the
initial partition, account, and credentials, then start the server against the same database with a
configuration file. The database schema is diagrammed in
[`docs/schema`](docs/schema).

## Documentation

Published automatically to docs.rs for each crate — for instance
[scratchstack-aws-signature](https://docs.rs/scratchstack-aws-signature/) and
[scratchstack-aspen](https://docs.rs/scratchstack-aspen/). Build the whole workspace's docs locally
with:

```sh
cargo doc --no-deps --workspace --open
```

## License

MIT. See [`Cargo.toml`](Cargo.toml) for workspace metadata; some crates carry their own `LICENSE`
files, such as [`scratchstack-aws-signature/LICENSE-MIT`](scratchstack-aws-signature/LICENSE-MIT).
