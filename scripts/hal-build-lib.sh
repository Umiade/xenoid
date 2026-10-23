#!/usr/bin/env bash
# Shared helpers for the AIDL HAL build scripts (sourced, not executed).
#
# xenoid_aidl_generate <aidl> <gen> <resolver> <aidl-args...>
#   Runs the AIDL compiler once per package directory instead of once per file.
#   <resolver> is a shell function that receives a representative .aidl path and
#   prints extra per-package arguments (e.g. "--version 1 --hash <sha>"), or
#   fails for an unknown package. Files are read NUL-separated from stdin.
#
# xenoid_compile_link <cxx> <output> <jobs>
#   Compiles every entry of the global SRCS array to an object in parallel with
#   the global CXXFLAGS array, then links them in SRCS order with CXXFLAGS and
#   the global LDFLAGS array. Equivalent to one "$CXX $CXXFLAGS -o out SRCS
#   LDFLAGS" driver call, but uses up to <jobs> compiler processes.

xenoid_aidl_generate() {
  local aidl_bin="$1" gen="$2" resolver="$3"
  shift 3
  local -a common=("$@")
  local file dir previous="" extra
  local -a batch=()
  local -a files=()
  while IFS= read -r -d '' file; do files+=("$file"); done
  [[ ${#files[@]} -gt 0 ]] || { printf 'no AIDL sources\n' >&2; return 1; }
  _xenoid_aidl_flush() {
    [[ ${#batch[@]} -gt 0 ]] || return 0
    extra="$("$resolver" "${batch[0]}")" || return 1
    # shellcheck disable=SC2086 # resolver output is a fixed flag list
    "$aidl_bin" "${common[@]}" $extra -o"$gen" -h"$gen" "${batch[@]}"
    batch=()
  }
  for file in "${files[@]}"; do
    dir="${file%/*}"
    if [[ "$dir" != "$previous" ]]; then
      _xenoid_aidl_flush || return 1
      previous="$dir"
    fi
    batch+=("$file")
  done
  _xenoid_aidl_flush || return 1
  unset -f _xenoid_aidl_flush
}

_xenoid_rsp_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"\n' "$value"
}

xenoid_compile_link() {
  local cxx="$1" output="$2" jobs="$3"
  [[ "$jobs" =~ ^[1-9][0-9]*$ ]] || jobs=1
  local root work rsp index flag
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  mkdir -p "$root/.tmp"
  work="$(mktemp -d "$root/.tmp/hal-objects.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: the trap must remove this run's dir
  trap "rm -rf '$work'" EXIT
  rsp="$work/cxxflags.rsp"
  : >"$rsp"
  for flag in "${CXXFLAGS[@]}"; do _xenoid_rsp_quote "$flag" >>"$rsp"; done
  local -a objects=()
  index=0
  for flag in "${SRCS[@]}"; do
    objects+=("$work/$index.o")
    index=$((index + 1))
  done
  index=0
  for flag in "${SRCS[@]}"; do
    printf '%s\0%s\0' "$flag" "${objects[$index]}"
    index=$((index + 1))
  done | xargs -0 -n 2 -P "$jobs" sh -c 'exec "$0" "@$1" -c "$2" -o "$3"' "$cxx" "$rsp" || {
    rm -rf "$work"
    trap - EXIT
    return 1
  }
  "$cxx" "@$rsp" -o "$output" "${objects[@]}" "${LDFLAGS[@]}" || {
    rm -rf "$work"
    trap - EXIT
    return 1
  }
  rm -rf "$work"
  trap - EXIT
}
