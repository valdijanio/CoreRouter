#!/bin/sh
# Runs after the packages are installed in $TARGET_DIR (= $1).
set -eu
T="$1"
# Mount points the init fills (the root is a read-only squashfs).
for d in config run tmp var sys/fs/bpf; do mkdir -p "$T/$d"; done
# The skeleton's /var symlinks point into /tmp; /var is its own tmpfs here.
rm -rf "$T/var"; mkdir -p "$T/var"
# No getty, no inittab, no rc scripts: corerouter-init is the only service
# manager (init=/usr/sbin/corerouter-init on the kernel command line).
rm -rf "$T/etc/init.d" "$T/etc/inittab"
cat > "$T/etc/os-release" <<EOR
NAME=CoreRouter
ID=corerouter
PRETTY_NAME="CoreRouter (${COREROUTER_COMMIT:-dev})"
VERSION_ID=${COREROUTER_COMMIT:-dev}
HOME_URL=https://github.com/valdijanio/CoreRouter
EOR
