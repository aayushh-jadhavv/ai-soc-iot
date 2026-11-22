#!/usr/bin/env bash
set -euo pipefail

case "${1:-base}" in
    base)
        flavor=base
        model=llama3_2-1B.pte
        tokenizer=tokenizer.model
        ;;
    instruct)
        flavor=instruct
        model=Llama-3.2-1B-Instruct.pte
        tokenizer=tokenizer-instruct.model
        ;;
    *)
        echo "Usage: bash prepare-model.sh [base|instruct]" >&2
        exit 2
        ;;
esac

adb_bin="$HOME/Android/Sdk/platform-tools/adb"
app="org.raspigateway.demo"
source_dir="/data/local/tmp/llama"
if [[ ! -x "$adb_bin" ]]; then
    adb_bin=adb
fi

"$adb_bin" -d shell "getprop ro.product.model"
"$adb_bin" -d shell "run-as $app mkdir -p files"
"$adb_bin" -d shell "test -s $source_dir/$model && test -s $source_dir/$tokenizer"

copy_file() {
    local source="$source_dir/$1"
    local target="files/llama-$flavor.$2"
    echo "Copying $1 within the phone…"
    "$adb_bin" -d shell "cat $source | run-as $app sh -c 'cat > $target.tmp'"
    "$adb_bin" -d shell "test \$(stat -c %s $source) -eq \$(run-as $app stat -c %s $target.tmp)"
}

copy_file "$model" pte
copy_file "$tokenizer" model
"$adb_bin" -d shell "run-as $app sh -c 'mv files/llama-$flavor.pte.tmp files/llama-$flavor.pte && mv files/llama-$flavor.model.tmp files/llama-$flavor.model'"
echo "Ready. Open a report in Gateway Reports and tap Explain report."
