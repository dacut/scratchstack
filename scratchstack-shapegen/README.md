# scratchstack-shapegen

Server-side Rust code generation from [Smithy](https://smithy.io/) model files.

This is the counterpart to the AWS Smithy generators: where those emit *client* types, shapegen emits
the request, response, error, and action types a *service implementation* needs. It is consumed only
from `build.rs`, by [`scratchstack-shapes-iam`](../scratchstack-shapes-iam) and
[`scratchstack-shapes-sts`](../scratchstack-shapes-sts).

## Output

A model is read, transformed, resolved, and written to five sinks:

| Sink | Contents |
|---|---|
| `action.rs` | The `Action` enum (wire operation names), `VERSION`, `FromStr`, `UnknownAction` |
| `operation.rs` | Operation input/output structures, their builders, and response envelopes |
| `types.rs` | Ordinary structures, enums, and unions |
| `types_error.rs` | Error structures and their `ProvideErrorMetadata`/`Responder` impls |
| `error_meta.rs` | The service-wide `Error` union enum and its forwarding impls |

Each is pulled into the consuming crate with
`include!(concat!(env!("OUT_DIR"), "/<name>.rs"))`.

## Measuring build cost

shapegen is often blamed for the workspace's slowest build step. It is not the cause: **generation is
about 4% of the cost, and compiling what it generates is about 66%.** Re-measure with the following
before optimizing anything.

### Where the wall time goes

```sh
cargo clean -p scratchstack-shapes-iam
cargo build --timings -p scratchstack-shapes-iam
open target/cargo-timings/cargo-timing-*.html
```

Cargo reports `build script (run)` — shapegen actually generating — as a unit distinct from the rustc
unit that compiles the result. That one chart answers "shapegen or rustc?".

### What rustc spends it on

```sh
cargo rustc -p scratchstack-shapes-iam --lib -- -Ztime-passes
cargo rustc -p scratchstack-shapes-iam --lib -- -Zself-profile=./prof && summarize summarize prof/*.mm_profdata
```

`-Ztime-passes` separates macro expansion (serde and bon derives) from codegen and LLVM. The workspace
is pinned to nightly in `rust-toolchain.toml`, so both are available without a toolchain override.

### What dominates codegen

```sh
cargo llvm-lines -p scratchstack-shapes-iam --lib | head -40
```

The distribution is very flat — no single item exceeds 0.2% — so read it by *category* rather than by
top-N. Note that every generated `Serialize` impl is monomorphized four times, once per `quick_xml`
serializer type.

### Volume proxies

```sh
OUT=$(ls -d target/debug/build/scratchstack-shapes-iam-*/out | head -1)
wc -l $OUT/*.rs
grep -c LazyLock $OUT/operation.rs
ls -l target/debug/deps/libscratchstack_shapes_iam-*.rmeta
```

### Incremental rebuild, which is what actually hurts

```sh
touch scratchstack-shapes-iam/build.rs && time cargo build -p scratchstack-shapes-iam
```

## Baseline — 2026-09-02

IAM model: 1,057,288 bytes, 749 shapes (353 structure, 176 operation, 115 string, 56 list, 27 enum).
Generated: 4.6 MB across 94,120 lines; `operation.rs` alone is 3.5 MB / 72,041 lines. rmeta: 20 MB.

Cold build of `scratchstack-shapes-iam` and its path dependencies — 28.47 s total:

| Unit | Time | Share |
|---|---|---|
| `scratchstack-shapes-iam` (rustc on generated code) | 18.78 s | 66% |
| `scratchstack-shapes-iam` build-script (compile) | 3.38 s | 12% |
| `scratchstack-shapegen` (compile) | 1.46 s | 5% |
| **`scratchstack-shapes-iam` build-script (run) — generation** | **1.06 s** | **4%** |
| `scratchstack-core`, `scratchstack-cli-utils` | 1.72 s | 6% |

rustc passes over the generated crate (warm incremental, 7.85 s total):

| Pass | Time | Share |
|---|---|---|
| `codegen_crate` / `codegen_to_LLVM_IR` | 2.26 s | 29% |
| `macro_expand_crate` | 1.79 s | 23% |
| `LLVM_passes` | 1.66 s | 21% |
| `serialize_dep_graph` | 0.76 s | 10% |
| `resolve_crate` | 0.34 s | 4% |
| `type_check_crate` | 0.27 s | 3% |

LLVM lines by category — 975,143 total across 23,951 copies:

| Category | Lines | Share | Copies |
|---|---|---|---|
| other | 322,485 | 33.1% | 8,608 |
| serde `Serialize` | 211,625 | 21.7% | 3,153 |
| CLI shorthand / `FromStr` (`clap` feature) | 197,225 | 20.2% | 4,224 |
| builder setters and `build()` | 132,909 | 13.6% | 3,552 |
| builder `validate()` | 84,769 | 8.7% | 2,084 |
| serde `Deserialize` | 11,233 | 1.2% | 1,162 |
| `Display`/`Debug` | 5,475 | 0.6% | 262 |
| error metadata | 4,920 | 0.5% | 523 |
| `Responder::respond` | 2,612 | 0.3% | 299 |
| regex statics | 1,890 | 0.2% | 84 |

Three conclusions worth keeping:

1. **Optimizing shapegen itself is not worth doing for build time.** Generation is 1.06 s of 28.47 s.
   String-allocation churn in the generator is a readability concern, not a performance one.
2. **The `clap` feature is the largest single lever.** It defaults on and every consumer takes the
   default, yet no consumer uses the generated shorthand impls. Building without it:
   975,143 → 730,669 LLVM lines (−25%) and 18.78 s → 15.85 s of rustc time (−15.6%).
3. **Macro expansion is already 23%.** Any change that adds proc-macro expansions to the generated
   crate — for example replacing hand-rolled builders with ~1,000 `#[bon::bon]` expansions — must be
   measured against this number before being adopted.
