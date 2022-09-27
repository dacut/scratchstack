#!/bin/bash -ex
ROOT=$(cd $(dirname $0); pwd)
llvm-cov report -Xdemangler=rustfilt \
    -use-color \
    -ignore-filename-regex='/.cargo/registry|.*thread/local.rs' \
    -instr-profile="$ROOT/arn/cov.profdata" \
    "$ROOT"/target/coverage/arn/debug/deps/scratchstack_arn-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]

llvm-cov report -Xdemangler=rustfilt \
    -use-color \
    -ignore-filename-regex='/.cargo/registry|.*thread/local.rs|arn/' \
    -instr-profile="$ROOT/principal/cov.profdata" \
    "$ROOT"/target/coverage/principal/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]
