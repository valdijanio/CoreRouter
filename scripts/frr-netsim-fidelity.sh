#!/usr/bin/env bash
# G3.7c: the simulator against a real FRR (crates/netsim/tests/frr_fidelity.rs
# builds one namespace and one FRR instance per router). Runs as root inside
# the lab VM only:
#   cargo xtask vm-lab run -- scripts/frr-netsim-fidelity.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
NETSIM_FRR_LIVE=1 cargo test -p corerouter-netsim --test frr_fidelity -- --nocapture
