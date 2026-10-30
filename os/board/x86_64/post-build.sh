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
# G1.6b: the Ed25519 public keys a system package must be signed with
# (`cargo xtask os build` exports the directory; the private key never
# enters the tree nor the image).
: "${CR_SEAL_IMAGE_KEYS_DIR:?run through cargo xtask os build}"
rm -rf "$T/etc/corerouter/image-keys"
mkdir -p "$T/etc/corerouter/image-keys"
cp "$CR_SEAL_IMAGE_KEYS_DIR"/*.pub "$T/etc/corerouter/image-keys/"
cat > "$T/etc/os-release" <<EOR
NAME=CoreRouter
ID=corerouter
PRETTY_NAME="CoreRouter (${COREROUTER_COMMIT:-dev})"
VERSION_ID=${COREROUTER_COMMIT:-dev}
HOME_URL=https://github.com/valdijanio/CoreRouter
EOR
# G1.6c: FRR. corerouter-init starts the daemons hal-frr drives (no
# frrinit.sh, watchfrr or bash); the daemon talks to their vty sockets
# (no vtysh, which is the only FRR binary that links readline). Out of the
# image: the scripts, vtysh/readline/bash (GPL-3.0, nothing needs them),
# python tools (no python in the image) and the daemons CoreRouter does not
# configure (docs/os-image.md, "FRR na imagem").
rm -f "$T/usr/bin/vtysh" "$T/bin/bash" "$T/usr/lib/libreadline."* "$T/usr/lib/libhistory."*
rm -f "$T/usr/sbin/frr" "$T/usr/sbin/frrinit.sh" "$T/usr/sbin/frrcommon.sh" \
	"$T/usr/sbin/watchfrr" "$T/usr/sbin/watchfrr.sh" "$T/usr/sbin/frr-reload" \
	"$T/usr/sbin/frr-reload.py" "$T/usr/sbin/frr_babeltrace.py" \
	"$T/usr/sbin/generate_support_bundle.py" "$T/usr/sbin/fpm_listener"
for d in babeld eigrpd fabricd isisd pathd pbrd pim6d pimd ripd ripngd vrrpd nhrpd sharpd; do
	rm -f "$T/usr/sbin/$d"
done
rm -f "$T/usr/lib/frr/modules/pathd_pcep.so" "$T/usr/lib/frr/modules/zebra_cumulus_mlag.so" \
	"$T/usr/lib/libstdc++.so.6.0.32-gdb.py"
# /etc/frr is read-only: the configuration lives in /config and reaches FRR
# through hal-frr; the daemons start empty. The files stay (the package's
# permission table names them), emptied.
for f in "$T"/etc/frr/*; do
	echo "! CoreRouter: FRR is configured by corerouter-daemon (hal-frr), not from here." > "$f"
done
# What only those needed (readline's ncurses, the C++ runtime the toolchain
# copies because FRR's configure wants a C++ compiler, PCRE2's POSIX layer).
# `cargo xtask os build` checks every ELF's NEEDED is still in the image.
# G1.6v: of e2fsprogs, corerouter-init runs e2fsck and resize2fs (growing
# /config); the other tools (mkfs, tune2fs, debugfs, …) leave the image.
for b in badblocks debugfs dumpe2fs e2freefrag e2image e2label e2mmpstatus e2undo e4crypt \
	e4defrag filefrag findfs fsck.ext2 fsck.ext3 fsck.ext4 logsave mke2fs mkfs.ext2 \
	mkfs.ext3 mkfs.ext4 mklost+found tune2fs; do
	rm -f "$T/sbin/$b" "$T/usr/sbin/$b"
done
rm -f "$T/usr/bin/chattr" "$T/usr/bin/lsattr" "$T/usr/bin/compile_et" "$T/usr/bin/mk_cmds" \
	"$T/etc/mke2fs.conf"
rm -rf "$T/usr/share/terminfo"
rm -f "$T"/usr/lib/libstdc++.so* "$T"/usr/lib/libgomp.so* "$T"/usr/lib/libncurses.so* \
	"$T"/usr/lib/libcurses.so "$T"/usr/lib/libform.so* "$T"/usr/lib/libmenu.so* \
	"$T"/usr/lib/libpanel.so* "$T"/usr/lib/libpcre2-posix.so* "$T/usr/bin/pcre2test" \
	"$T/usr/bin/pcre2grep" "$T/usr/bin/yanglint" "$T/usr/bin/yangre" "$T/usr/bin/mtracebis"
