#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
export out CXX=${CXX:-c++}
run_one() {
    local file=$1 name exe
    name=$(basename "$file" .cpp)
    exe=$out/$name
    local extra=() args=()
    case "$name" in
        guest_test|cpu64_test|guest_memory_test|loader_test) extra=(app/src/main/cpp/guest.cpp app/src/main/cpp/pe.cpp);;
        scarlett_import_entry_test|scarlett_real_pe_test) args=(app/src/main/assets/doors.exe);;
    esac
    "$CXX" -std=c++20 -Wall -Wextra -Werror -Iapp/src/main/cpp "$file" "${extra[@]}" -o "$exe" >"$exe.log" 2>&1 &&
        "$exe" "${args[@]}" >>"$exe.log" 2>&1 && { echo "PASS $name"; return 0; }
    echo "FAIL $name"
    cat "$exe.log"
    return 1
}
export -f run_one
printf '%s\0' tests/*_test.cpp | xargs -0 -n1 -P "${JOBS:-3}" bash -c 'run_one "$1"' _
