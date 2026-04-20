#!/usr/bin/env bash
set -euo pipefail

PROGRAM_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"${PROGRAM_ROOT}/bootstrap/setup_and_run_fleet_commander.sh"

echo
read -r -p "Press Enter to close..." _
