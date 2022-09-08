#!/bin/bash
mkdir -p coverage-html
find coverage-html -type f -delete
llvm-cov show \
    -format=html \
    -ignore-filename-regex='/.cargo/registry|.*thread/local.rs' \
    -Xdemangler=rustfilt \
    -output-dir=coverage-html \
    -instr-profile=scratchstack-core.profdata \
    target/debug/deps/scratchstack_arn-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    -object target/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]

case $(uname -s) in
    Darwin )
        open coverage-html/index.html
        ;;
    Linux )
        xdg-open coverage-html/index.html
        ;;
esac
