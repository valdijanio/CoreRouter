#!/bin/sh
# Runs with the images in $BINARIES_DIR: the kernel (EFI stub) becomes the
# ESP's default loader, then genimage writes disk.img.
set -eu
mkdir -p "$BINARIES_DIR/efi-part/EFI/BOOT"
cp "$BINARIES_DIR/bzImage" "$BINARIES_DIR/efi-part/EFI/BOOT/BOOTX64.EFI"
exec support/scripts/genimage.sh -c "$BR2_EXTERNAL_COREROUTER_PATH/board/x86_64/genimage.cfg"
