#!/bin/bash
ROOT=$(cd $(dirname $0); pwd)
rm -f *.profdata *.profraw
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$ROOT/scratchstack-core-%m.profraw"
cargo clean
(cd arn && cargo test --tests)
(cd principal && cargo test --tests)
llvm-profdata merge -sparse scratchstack-core-*.profraw -o scratchstack-core.profdata
