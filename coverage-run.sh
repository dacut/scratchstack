#!/bin/bash
export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="scratchstack-aws-principal-%m.profraw"
rm -f scratchstack-aws-principal*.profraw
cargo test --features service
rm -f scratchstack-aws-principal*.profdata
cargo profdata -- merge -sparse scratchstack-aws-principal*.profraw -o scratchstack-aws-principal.profdata
