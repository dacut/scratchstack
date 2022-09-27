#!/bin/bash
ROOT=$(cd $(dirname $0); pwd)
mkdir -p "$ROOT/coverage-html"
find "$ROOT/coverage-html" -type f -delete
llvm-cov show \
    -format=html \
    -ignore-filename-regex='/.cargo/registry|.*thread/local.rs' \
    -Xdemangler=rustfilt \
    -output-dir="$ROOT/coverage-html/scratchstack-arn" \
    -instr-profile="$ROOT/arn/cov.profdata" \
    "$ROOT"/target/coverage/arn/debug/deps/scratchstack_arn-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]

llvm-cov show \
    -format=html \
    -ignore-filename-regex='/.cargo/registry|.*thread/local.rs|arn/' \
    -Xdemangler=rustfilt \
    -output-dir="$ROOT/coverage-html/scratchstack-aws-principal" \
    -instr-profile="$ROOT/principal/cov.profdata" \
    "$ROOT"/target/coverage/principal/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]


case $(uname -s) in
    Darwin )
        open "$ROOT/coverage-html/scratchstack-arn/index.html";
        open "$ROOT/coverage-html/scratchstack-aws-principal/index.html";
        ;;
    Linux )
        xdg-open "$ROOT/coverage-html/scratchstack-arn/index.html";
        xdg-open "$ROOT/coverage-html/scratchstack-aws-principal/index.html";
        ;;
esac
