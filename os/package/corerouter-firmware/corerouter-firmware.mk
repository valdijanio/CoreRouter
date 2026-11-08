################################################################################
#
# corerouter-firmware: NIC firmware of the image (G1.6j, docs/os-image.md)
#
# No download here: `cargo xtask os build` fetches the files firmware.lock
# pins (hash checked) and stages them in COREROUTER_FIRMWARE_STAGE, because
# Buildroot's linux-firmware package needs the whole tarball (over 600 MB) for
# a few MB. The stage is lib/firmware/... and usr/share/licenses/firmware/.
# The files stay uncompressed: the squashfs compresses them, and the kernel
# needs no decompressor (CONFIG_FW_LOADER_COMPRESS off).
#
################################################################################

COREROUTER_FIRMWARE_VERSION = 1
COREROUTER_FIRMWARE_SOURCE =
COREROUTER_FIRMWARE_LICENSE = Proprietary (redistributable; usr/share/licenses/firmware)
COREROUTER_FIRMWARE_STAGE ?=

define COREROUTER_FIRMWARE_INSTALL_TARGET_CMDS
	test -d "$(COREROUTER_FIRMWARE_STAGE)/lib/firmware" || \
		{ echo "COREROUTER_FIRMWARE_STAGE: no firmware (build with cargo xtask os build)"; exit 1; }
	rm -rf $(TARGET_DIR)/lib/firmware $(TARGET_DIR)/usr/share/licenses/firmware
	mkdir -p $(TARGET_DIR)/usr/share/licenses
	cp -a $(COREROUTER_FIRMWARE_STAGE)/lib/. $(TARGET_DIR)/lib/
	cp -a $(COREROUTER_FIRMWARE_STAGE)/usr/share/licenses/firmware $(TARGET_DIR)/usr/share/licenses/
endef

$(eval $(generic-package))
