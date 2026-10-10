#!/bin/sh
set -eu
cd "$(dirname "$0")/elf"
exec ./check.sh
