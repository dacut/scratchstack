#!/bin/bash -ex
CLEAN=1
ROOT=$(cd $(dirname $0); pwd)

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-clean)
            CLEAN=0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

find "$ROOT" -name "*.profdata" -delete -o -name "*.profraw" -delete

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0"
if [[ $CLEAN -ne 0 ]]; then
    cargo clean --target-dir "$ROOT/target/coverage/arn"
    cargo clean --target-dir "$ROOT/target/coverage/principal"
fi

(cd "$ROOT/arn" &&
    LLVM_PROFILE_FILE="$ROOT/arn/cov-%m.profraw" cargo test --target-dir "$ROOT/target/coverage/arn")
(cd "$ROOT/principal" &&
    LLVM_PROFILE_FILE="$ROOT/principal/cov-%m.profraw" cargo test --target-dir "$ROOT/target/coverage/principal")
llvm-profdata merge -sparse "$ROOT"/arn/cov-*.profraw -o "$ROOT/arn/cov.profdata"
llvm-profdata merge -sparse "$ROOT"/principal/cov-*.profraw -o "$ROOT/principal/cov.profdata"

llvm-cov export -format lcov -Xdemangler=rustfilt -ignore-filename-regex='/.cargo/registry|.*thread/local.rs' \
    -instr-profile="$ROOT/arn/cov.profdata" \
    target/coverage/arn/debug/deps/scratchstack_arn-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    > "$ROOT/scratchstack-arn.lcov"

llvm-cov export -format lcov -Xdemangler=rustfilt -ignore-filename-regex='/.cargo/registry|.*thread/local.rs|arn/' \
    -instr-profile="$ROOT/principal/cov.profdata" \
    target/coverage/principal/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    > "$ROOT/scratchstack-aws-principal.lcov"

"$ROOT/coverage-fixup.py" "$ROOT/scratchstack-arn.lcov"
"$ROOT/coverage-fixup.py" "$ROOT/scratchstack-aws-principal.lcov"
cat "$ROOT/scratchstack-arn.lcov" "$ROOT/scratchstack-aws-principal.lcov" > "$ROOT/scratchstack-core.lcov"
