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
# G1.30: cfg80211's regulatory.db and its signature are wireless-regdb's, not
# linux-firmware's. That package installs them once; `cargo xtask os build`
# then empties lib/firmware of every package at each build (the files of an
# older firmware.lock must not pile up) and only this package fills it again,
# so the second build of a tree lost them ("cfg80211: failed to load
# regulatory.db", no country, 5 GHz listen-only). They are installed here,
# from that package's build directory, every time.
COREROUTER_FIRMWARE_DEPENDENCIES = wireless-regdb

define COREROUTER_FIRMWARE_INSTALL_TARGET_CMDS
	test -d "$(COREROUTER_FIRMWARE_STAGE)/lib/firmware" || \
		{ echo "COREROUTER_FIRMWARE_STAGE: no firmware (build with cargo xtask os build)"; exit 1; }
	rm -rf $(TARGET_DIR)/lib/firmware $(TARGET_DIR)/usr/share/licenses/firmware
	mkdir -p $(TARGET_DIR)/usr/share/licenses
	cp -a $(COREROUTER_FIRMWARE_STAGE)/lib/. $(TARGET_DIR)/lib/
	cp -a $(COREROUTER_FIRMWARE_STAGE)/usr/share/licenses/firmware $(TARGET_DIR)/usr/share/licenses/
	$(INSTALL) -m 644 -D $(WIRELESS_REGDB_DIR)/regulatory.db \
		$(TARGET_DIR)/lib/firmware/regulatory.db
	$(INSTALL) -m 644 -D $(WIRELESS_REGDB_DIR)/regulatory.db.p7s \
		$(TARGET_DIR)/lib/firmware/regulatory.db.p7s
	$(INSTALL) -m 644 -D $(WIRELESS_REGDB_DIR)/LICENSE \
		$(TARGET_DIR)/usr/share/licenses/firmware/LICENSE.wireless-regdb
endef

$(eval $(generic-package))
