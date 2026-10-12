#!/usr/bin/env bash
# Replays all inherited add-host and ended-strip functional assertions on one owned port.
set -euo pipefail
umask 022
export PATH=/home/kayg/.nix-profile/bin:$PATH
export TRACER_TEST_PORT=4977
cd apps/tracer
bun x playwright test -c ../../evidence/dev-backmerge-prod5/playwright.functional.config.mts --timeout=120000 test/addhost-wizard.spec.ts test/addhost-start-fresh-captures.spec.ts test/ended-strip.spec.ts
