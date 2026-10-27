#!/bin/sh
# Runs with the images in $BINARIES_DIR. `corerouter-image seal` (G1.6b)
# appends the dm-verity tree to the squashfs (rootfs.img), signs the
# manifest, writes the update package and fills the ESP (slot A's kernel as
# BOOTX64.EFI, its signed header); then genimage writes disk.img.
set -eu
# mke2fs and the e2fsck genimage runs on the config partition stamp the
# superblock with the current time unless told otherwise: the image would
# differ on every build. SOURCE_DATE_EPOCH comes from BR2_REPRODUCIBLE.
export E2FSPROGS_FAKE_TIME="${SOURCE_DATE_EPOCH:?BR2_REPRODUCIBLE sets it}"
export E2FSCK_TIME="$SOURCE_DATE_EPOCH"
rm -rf "$BINARIES_DIR/efi-part"
"${CR_SEAL_TOOL:?run through cargo xtask os build}" seal "$BINARIES_DIR"
exec support/scripts/genimage.sh -c "$BR2_EXTERNAL_COREROUTER_PATH/board/x86_64/genimage.cfg"
