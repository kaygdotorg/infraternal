#!/usr/bin/env bash
# Use the lane's documented native gate profile without changing dependencies or release builds, #173.
set -euo pipefail
exec /home/kayg/.nix-profile/bin/cargo --config /home/kayg/Developer/infraternal/.worktrees/mesh-policy-verify/docs/verification/mesh-policy-verify/gates/gate-profile.toml "$@"
