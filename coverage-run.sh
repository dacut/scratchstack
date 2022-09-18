#!/bin/bash
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

rm -f *.profdata *.profraw

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Ccodegen-units=1 -Cinstrument-coverage -Copt-level=0"
export LLVM_PROFILE_FILE="$ROOT/scratchstack-core-%m.profraw"
if [[ $CLEAN -ne 0 ]]; then
    cargo clean
fi
(cd arn && cargo test --tests)
(cd principal && cargo test --tests)
llvm-profdata merge -sparse scratchstack-core-*.profraw -o scratchstack-core.profdata
