#!/usr/bin/env bash
# G3.7c: the simulator against a real FRR (crates/netsim/tests/frr_fidelity.rs
# builds one namespace and one FRR instance per router). Runs as root inside
# the lab VM only:
#   cargo xtask vm-lab run -- scripts/frr-netsim-fidelity.sh
set -euo pipefail
# vm-lab run holds its lock on fd 9: a daemon started from here would
# inherit it and keep the VM locked after the round.
exec 9>&-
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
# The test tears its routers down; this also covers a killed test.
cleanup() {
  pkill -f -- "-N crs" 2>/dev/null || true
  for n in $(ip netns list | awk '/^crs/ {print $1}'); do ip netns del "$n" || true; done
}
trap cleanup EXIT
NETSIM_FRR_LIVE=1 cargo test -p corerouter-netsim --test frr_fidelity -- --nocapture
