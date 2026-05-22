#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <local-PARAMS> <reference-PARAMS>" >&2
  exit 2
fi

local_params=$1
reference_params=$2

normalize() {
  sed \
    -e 's/[[:space:]]*#.*$//' \
    -e 's/[[:space:]]*\/\/.*$//' \
    -e '/^[[:space:]]*$/d' \
    -e 's/[[:space:]][[:space:]]*/ /g' \
    -e 's/^[[:space:]]*//' \
    -e 's/[[:space:]]*$//' \
    "$1" | sort
}

diff -u \
  <(normalize "$local_params") \
  <(normalize "$reference_params")
