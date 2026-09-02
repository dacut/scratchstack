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

shapegen is often blamed for the workspace's slowest build step. It is not the cause: on a cold build
of `scratchstack-shapes-iam` and its path dependencies, **rustc on the generated code is about 73% of
the cost and generating it is about 4%.** The lever is the volume of code generated, not the speed of
the generator.

Re-measure with the following before optimizing anything. Every figure here is from one machine, and
the ratios travel better than the seconds do.

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
# Pick the out dir by the mtime of what is in it. Older cargo versions left behind
# `build/<pkg>-<hash>/out` directories that `ls -t` will happily hand you instead, and comparing
# against one of those quietly compares a snapshot with itself.
OUT=$(find target/debug/build -name operation.rs -path '*/scratchstack-shapes-iam/*/out/*' \
      -exec stat -f '%m %N' {} \; | sort -rn | head -1 | cut -d' ' -f2- | xargs dirname)
wc -l $OUT/*.rs
cat $OUT/*.rs | grep -c LazyLock
```

Compare rmeta or rlib sizes only between builds made the same way -- a `cargo check` metadata file and
a `cargo build` one differ by more than the code does, which makes the comparison meaningless.

### Incremental rebuild, which is what actually hurts

```sh
touch scratchstack-shapes-iam/build.rs && time cargo build -p scratchstack-shapes-iam
```

## Baseline — 2026-09-02

IAM model: 1,057,288 bytes, 749 shapes (353 structure, 176 operation, 115 string, 56 list, 27 enum).
Generated: 4.6 MB across 94,120 lines; `operation.rs` alone is 3.5 MB / 72,041 lines.

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

1. **Optimizing shapegen itself is not worth doing for build time.** Generation was 1.06 s of the
   28.47 s above, and is about 0.9 s of 21 s today -- the ratio has held through every change since.
   String-allocation churn in the generator is a readability concern, not a performance one.
2. **CLI shorthand parsers were the largest single lever**, and are the reason
   [`CliShorthand`] defaults to value types only. Operation request structures were each getting
   three `#[cfg(feature = "clap")]` parser impls -- 858 of the 1,041 generated -- for a syntax that
   only ever supplies a *nested value* to a flag. No caller parsed one.
3. **Macro expansion is already 23%.** Any change that adds proc-macro expansions to the generated
   crate -- for example replacing hand-rolled builders with ~1,000 `#[bon::bon]` expansions -- must
   be measured against this number before being adopted.

## After restricting CLI shorthand to value types

| Measure | Before | After | Change |
|---|---|---|---|
| Generated lines (IAM) | 94,120 | 80,160 | −14.8% |
| `operation.rs` lines | 72,041 | 58,081 | −19.4% |
| clap-gated impls | 1,041 | 183 | −82.4% |
| LLVM lines | 975,143 | 768,592 | −21.2% |
| LLVM copies | 23,951 | 18,434 | −23.0% |
| rustc time | 18.78 s | 15.65 s | −16.7% |
| Build-script run | 1.06 s | 0.33 s | −68.9% |

The build-script figure also includes the buffered writers; the rest is having less to write.

## After porting emission to `quote!`

| Measure | writeln! | quote! |
|---|---|---|
| rustc time | 14.55 s | 14.75 s |
| Build-script run | 0.33 s | 2.00 s, or 0.64 s optimized (below) |
| Generated lines (IAM) | 73,893 | 84,835 |
| shapegen source | 4,912 | 4,819 |

`prettyplease` wraps more aggressively than the hand-written writers did, hence the extra generated
lines; rustc does not care, and the compile time is unchanged.

Cargo compiles build scripts with the dev profile, which for this one costs about four times its own
runtime. `[profile.dev.build-override] opt-level = 3` in the workspace manifest brings the run to
0.64 s, so the formatting and syntax check cost about 0.3 s over the `writeln!` implementation rather
than 1.7 s. It pays for itself across the workspace: proc macros are compiled under the same profile,
and `macro_expand_crate` is 23% of rustc's time on the generated crate. A full `cargo build
--workspace` measured the same either way, so the one-off cost of compiling the macros optimized is
already repaid.

## After hoisting validators

Constraints belong to the shape, not to each field targeting it, so each constrained shape now emits
one `pub(crate) fn validate_<shape>(value, field)` into `crate::types` and every builder field calls
it. Lists call their element shape's function rather than inlining its checks.

| Measure | Baseline | After shorthand | After hoisting |
|---|---|---|---|
| Generated lines (IAM) | 94,120 | 80,160 | **73,893** (−21.5%) |
| `operation.rs` lines | 72,041 | 58,081 | **51,533** (−28.5%) |
| `LazyLock<Regex>` statics | 694 | 694 | **55** (−92.1%) |
| Inline constraint checks | ~2,335 | ~2,335 | **182** (−92.2%) |
| LLVM lines | 975,143 | 768,592 | **728,623** (−25.3%) |
| LLVM copies | 23,951 | 18,434 | **17,017** (−29.0%) |
| rustc time | 18.78 s | 15.65 s | **14.55 s** (−22.5%) |
| Build-script run | 1.06 s | 0.33 s | **0.33 s** |

Note that the regex statics were never the build-time cost they looked like -- they were 0.2% of LLVM
lines. What hoisting actually removed was the `validate()` bodies, which were 8.7%. The statics
mattered for a different reason: 694 of them meant compiling `^[\w+=,.@-]+$` 235 times at runtime,
on first use, in every process that touched an IAM request.

## Emitting code

Generators build a `proc_macro2::TokenStream` with `quote!` and append it to one of the five
[`Modules`]. `Modules::write_to` renders each through `syn::parse2` and `prettyplease` and writes it
out. Nothing writes formatted text: the generator reads like the code it emits, brace matching is the
compiler's problem rather than the author's, and a generator bug surfaces as a parse error naming the
module instead of a rustc syntax error tens of thousands of lines into `operation.rs`.

Two consequences worth knowing:

* **`//` comments do not survive.** Only `#[doc]` attributes reach the output, so an explanation of
  why some generated `#[allow(...)]` is there has to live in the generator, not the generated file.
* **Rendering is most of the generation time.** Unoptimized, for the IAM model: 865 ms to render
  against 263 ms to build the tokens, plus 19 ms to parse the model and 2 ms to resolve it. That
  buys the syntax check and readable output; the alternative is `TokenStream::to_string`, which
  emits one enormous line. Optimizing the build script (above) cuts the whole thing to about a
  quarter.

## Compiling what it generates

`scratchstack-shapes-iam` and `scratchstack-shapes-sts` between them use structures, operations,
strings, lists, enums, integers, maps, booleans, blobs, timestamps and a service -- but no union and
no `intEnum`. Nothing compiled the code generated for the kinds they leave out, and three bugs lived
there undetected until a reviewer asked about one of them.

`scratchstack-shapegen-conformance` closes that: its `build.rs` generates from a model exercising
every shape kind, and the crate compiles the result as part of `cargo build --workspace`. Its tests
pin the wire forms that compiling alone does not check -- an `intEnum` encoding its discriminant, a
union externally tagged by member name. Add a shape kind, add it to `conformance-model.json`.

Note what the shapegen unit tests can and cannot do: they render tokens and assert on the text, and
`syn::parse2` catches a *syntax* error, but neither notices a semantically invalid attribute such as
`#[serde(tag = ...)]` on a variant. Only compiling the output finds those.

## Known loose ends

Things that are deliberate, or at least known, so they are not rediscovered as bugs:

* **`TraitId` is a closed set.** `trait_id.rs` enumerates the ~30 Smithy and AWS traits shapegen
  understands, and an unrecognized trait id in a model is a hard deserialization failure rather than
  something skipped. That is fine for two pinned models and will break the first time an updated AWS
  model introduces a trait. An `Unknown(String)` variant would fix it.
* **`scratchstack-sts-ext.json` is inert.** Its five shapes -- `markerType`, `maxItemsType`,
  `idType`, `booleanType`, `stringType` -- are referenced by nothing in `sts-2011-06-15.json`, and
  primitives emit no code of their own, so the file currently contributes nothing to the build. They
  look like groundwork for paginated STS operations; the pagination pair in particular mirrors IAM's.
* **The two services handle bad documentation differently.** IAM repairs angle-bracketed placeholders
  through `doc_rewrites`; STS instead carries `#[allow(rustdoc::invalid_html_tags)]` on its
  `operation` module. The allow is still load-bearing -- removing it produces one
  "improperly nested Markdown paragraph" warning -- but a targeted `doc_rewrite` would be the
  consistent fix.
* **`rust_typename` still returns `String`.** Several implementations compute it (`crate::types::X`,
  `Vec<T>`) rather than returning a cached field, and `Member` reaches through an
  `Rc<RefCell<Shape>>`, so it cannot hand out a borrow. `smithy_name` has the same constraint. The
  allocations are still not worth a `Cow` in the signature: they fall in the token-building phase,
  which is 263 ms of a build where rustc spends 15 s on the result, and an optimized build script
  cuts even that by roughly four.
