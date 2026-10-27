#!/bin/sh
# Runs with the images in $BINARIES_DIR: the kernel (EFI stub) becomes the
# ESP's default loader, then genimage writes disk.img.
set -eu
# mke2fs and the e2fsck genimage runs on the config partition stamp the
# superblock with the current time unless told otherwise: the image would
# differ on every build. SOURCE_DATE_EPOCH comes from BR2_REPRODUCIBLE.
export E2FSPROGS_FAKE_TIME="${SOURCE_DATE_EPOCH:?BR2_REPRODUCIBLE sets it}"
export E2FSCK_TIME="$SOURCE_DATE_EPOCH"
mkdir -p "$BINARIES_DIR/efi-part/EFI/BOOT"
cp "$BINARIES_DIR/bzImage" "$BINARIES_DIR/efi-part/EFI/BOOT/BOOTX64.EFI"
exec support/scripts/genimage.sh -c "$BR2_EXTERNAL_COREROUTER_PATH/board/x86_64/genimage.cfg"
