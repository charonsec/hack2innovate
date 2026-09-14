#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../deps" 2>/dev/null || { mkdir -p "$(dirname "$0")/../deps"; cd "$(dirname "$0")/../deps"; }
[ -d oz ]        || git clone --depth 1 --branch v5.0.2 https://github.com/OpenZeppelin/openzeppelin-contracts.git oz
[ -d chainlink ] || git clone --depth 1 --branch v1.3.0 https://github.com/smartcontractkit/chainlink.git chainlink
echo "deps OK: $(pwd)"
