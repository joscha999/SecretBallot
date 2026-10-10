#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../SecretBallot.Server/wwwroot"
find . -type f | LC_ALL=C sort | xargs sha256sum
