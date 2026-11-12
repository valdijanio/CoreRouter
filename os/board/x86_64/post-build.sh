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
# G1.6g: GRUB lives on the ESP and in the disk's first blocks; its recipe
# also leaves a sample configuration here.
rm -rf "$T/boot/grub"
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
# G1.30: wpa_supplicant gets its networks from corerouter-daemon, through
# its control socket, and keeps them in memory. The package's sample
# configuration joins any open network in range (`network={ key_mgmt=NONE }`):
# it must not be in the image, where a stray `-c` would use it.
rm -f "$T/etc/wpa_supplicant.conf" "$T/etc/network/if-up.d/wpasupplicant" \
	"$T/etc/network/if-down.d/wpasupplicant"
# It links libnl-3 and libnl-genl-3 (nl80211) and OpenSSL's libcrypto and
# libssl (SAE's elliptic curves; no TLS without EAP, but the link names it).
# The rest of the two packages leaves the image: libnl's route, netfilter,
# xfrm and sock-diag libraries with their tables, OpenSSL's sample files.
# `legacy.so` stays: RC4 for the group key of an old WPA/WPA2 mixed network.
rm -f "$T"/usr/lib/libnl-route-3.so* "$T"/usr/lib/libnl-nf-3.so* \
	"$T"/usr/lib/libnl-idiag-3.so* "$T"/usr/lib/libnl-xfrm-3.so*
rm -rf "$T/etc/libnl" "$T/etc/ssl/misc"
rm -f "$T"/etc/ssl/*.dist "$T/etc/ssl/ct_log_list.cnf"
# G1.30a: hostapd is the image's access point (the router in `mode=ap`,
# driven through its control socket, no configuration file). A copy is also
# the test's tool: the access point `cargo xtask os wifi-test` puts in front
# of the image's station runs from a disk of its own, with its own file.
if [ -f "$T/usr/sbin/hostapd" ]; then
	mkdir -p "$BINARIES_DIR/test-tools"
	cp "$T/usr/sbin/hostapd" "$BINARIES_DIR/test-tools/hostapd"
fi
rm -f "$T/usr/bin/hostapd_cli" "$T/etc/hostapd.conf"
# G1.6zr: pci.ids (hwdata) only for the PCI network cards the image's drivers
# bind: the ids in the pci: aliases of the modules and built-ins under
# drivers/net and of virtio_pci (a VM's virtio-net card is a PCI device of
# its), named from the full database (vendor and device lines; the
# subsystem lines and the classes go). interface.hardware and the health
# check name a card from it (hal-linux pci_ids); `cargo xtask os build`
# checks it still names the cards of docs/os-image.md.
IDS="$T/usr/share/hwdata/pci.ids"
if [ -f "$IDS" ]; then
	MODS=$(ls -d "$T"/lib/modules/*/ | head -n 1)
	{
		echo "M virtio_pci"
		awk -F: '$1 ~ /\/drivers\/net\// { n = $1; sub(/.*\//, "", n); sub(/\.ko.*/, "", n); gsub(/-/, "_", n); print "M " n }' "$MODS/modules.dep"
		awk '/\/drivers\/net\// { n = $0; sub(/.*\//, "", n); sub(/\.ko.*/, "", n); gsub(/-/, "_", n); print "M " n }' "$MODS/modules.builtin"
		awk '$1 == "alias" && $2 ~ /^pci:v/ { n = $NF; gsub(/-/, "_", n); print "A " n " " $2 }' "$MODS/modules.alias"
		tr '\0' '\n' < "$MODS/modules.builtin.modinfo" |
			awk -F'.alias=' 'NF == 2 && $2 ~ /^pci:v/ { n = $1; gsub(/-/, "_", n); print "A " n " " $2 }'
	} | awk '
		$1 == "M" { net[$2] = 1; next }
		$1 == "A" && ($2 in net) {
			v = tolower(substr($3, 10, 4)); d = tolower(substr($3, 19, 4))
			if (substr($3, 6, 1) == "*") next
			if (substr($3, 15, 1) == "*") print "V " v; else print "D " v " " d
		}' | sort -u > "$IDS.want"
	awk '
		FILENAME == ARGV[1] { if ($1 == "V") wild[$2] = 1; else { dev[$2 " " $3] = 1; vend[$2] = 1 } next }
		/^#/ { if (!seen) print; next }
		/^C / { exit }
		/^\t\t/ || /^[ \t]*$/ { next }
		/^\t/ { seen = 1; if (cur != "" && ((cur " " substr($0, 2, 4)) in dev || cur in wild)) print; next }
		{ seen = 1; cur = ""; if (substr($0, 1, 4) in vend || substr($0, 1, 4) in wild) { cur = substr($0, 1, 4); print } }
	' "$IDS.want" "$IDS" > "$IDS.net"
	mv "$IDS.net" "$IDS"
	rm -f "$IDS.want"
fi
