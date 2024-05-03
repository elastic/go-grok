#!/bin/bash
set -euo pipefail

buildkite-agent artifact download "output-*.report" .
ls *.report | xargs -I{} sh -c 'go-junit-report > "$1-junit.xml" < $1' -- {}