#!/bin/bash
export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="scratchstack-aws-principal-%m.profraw"
target=target/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]
cargo cov -- report \
    --use-color --ignore-filename-regex='/.cargo/registry' \
    --instr-profile=scratchstack-aws-principal.profdata \
    --object $target \
    "$@"