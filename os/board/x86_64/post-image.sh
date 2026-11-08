#!/bin/sh
# Runs with the images in $BINARIES_DIR. `corerouter-image seal` (G1.6b)
# appends the dm-verity tree to the squashfs (rootfs.img), signs the
# manifest, writes the update package and fills the ESP (slot A's kernel as
# BOOTX64.EFI, its signed header); then genimage writes disk.img (and the
# installer's boot image), and `corerouter-image installer` the installer
# ISO from them (G1.6c).
set -eu
# mke2fs and the e2fsck genimage runs on the config partition stamp the
# superblock with the current time unless told otherwise: the image would
# differ on every build. SOURCE_DATE_EPOCH comes from BR2_REPRODUCIBLE.
export E2FSPROGS_FAKE_TIME="${SOURCE_DATE_EPOCH:?BR2_REPRODUCIBLE sets it}"
export E2FSCK_TIME="$SOURCE_DATE_EPOCH"
rm -rf "$BINARIES_DIR/efi-part"
"${CR_SEAL_TOOL:?run through cargo xtask os build}" seal "$BINARIES_DIR"
# G1.6e: `cargo xtask os build --only crpkg` wants only the update package
# (the fast test cycle: build, `os push`, reboot): no disk.img nor ISO.
if [ -n "${CR_ONLY_CRPKG:-}" ]; then
	exit 0
fi
# G1.6g: GRUB's images for a BIOS (docs/os-image.md, "Boot por BIOS"): the
# disk's, with the prefix on the disk the BIOS booted; the installer's two
# (El Torito and stick), whose few commands use GRUB's rescue parser and pass
# no command line (the installer kernel's built-in one holds).
GRUB_MODS=$(echo "$BUILD_DIR"/grub2-*/build-i386-pc/grub-core)
B="$BINARIES_DIR/bios"
rm -rf "$B"
mkdir -p "$B"
: >"$B/empty.cfg"
printf 'loopback loop (cd)/EFIBOOT.IMG\nlinux (loop)/EFI/BOOT/BOOTX64.EFI\nboot\n' >"$B/cd.cfg"
printf 'linux /EFI/BOOT/BOOTX64.EFI\nboot\n' >"$B/usb.cfg"
mkimage() { "$HOST_DIR/bin/grub-mkimage" -d "$GRUB_MODS" "$@"; }
mkimage -O i386-pc -p '(,gpt1)/corerouter' -c "$B/empty.cfg" -o "$B/disk.core" \
	biosdisk part_gpt fat normal linux loadenv test echo serial terminal configfile
mkimage -O i386-pc-eltorito -p '(cd)/' -c "$B/cd.cfg" -o "$B/cd.img" \
	biosdisk iso9660 loopback fat linux part_gpt
mkimage -O i386-pc -p '(,gpt1)/' -c "$B/usb.cfg" -o "$B/usb.core" \
	biosdisk fat linux part_gpt
cp "$GRUB_MODS/boot.img" "$B/boot.img"
support/scripts/genimage.sh -c "$BR2_EXTERNAL_COREROUTER_PATH/board/x86_64/genimage.cfg"
exec "$CR_SEAL_TOOL" installer "$BINARIES_DIR"
