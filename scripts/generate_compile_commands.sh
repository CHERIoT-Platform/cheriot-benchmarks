#!/usr/bin/env bash

# Generate compile commands files for all known projects in this repo


. "$(dirname $0)"/common.sh

ensure_cheriot_benchmarks_root

find_sdk $1

echo "Using SDK=$SDK"

# Generate compile_commands.json for all of the benchmarks.
for dir in $BENCHMARKS; do
    echo Generating compile_commands.json for $dir
    (cd $dir && xmake f --sdk="${SDK}" && xmake project -k compile_commands --lsp=clangd)
done
