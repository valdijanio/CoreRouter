################################################################################
#
# corerouter-installer: the installer's kernel (G1.6c, docs/os-image.md)
#
# The same kernel tarball (shared download, same hash) and the image's
# final .config, with os/board/x86_64/installer.fragment on top: the
# installer's command line (corerouter.mode=live, no root=), an
# embedded initramfs and no BTF (the installer loads no eBPF). The
# initramfs is a gen_init_cpio list (fixed owners and modes: reproducible)
# with corerouter-init as /init, the libraries it links, the public image
# keys the payload must be signed with, and busybox for the live image's move
# to its root (G1.6y: `mount -o loop`, `switch_root`; no `unsafe` ioctl in
# the init).
#
# G1.6za: this kernel's modules too, in a squashfs of their own
# (live-modules.img), which `corerouter-image installer` puts on the ISO and in
# its signed index. The live image mounts it over /lib/modules. Not in the
# initramfs: the boot image has a 32 MiB limit, and a card the machine does not
# have would cost RAM on every boot.
#
# `cargo xtask os build` drops this package's build stamp on every build
# (the init is the workspace's, $(COREROUTER_OUT)): kbuild then relinks only
# the initramfs and vmlinux.
#
################################################################################

COREROUTER_INSTALLER_VERSION = $(LINUX_VERSION)
COREROUTER_INSTALLER_SOURCE = linux-$(LINUX_VERSION).tar.xz
COREROUTER_INSTALLER_SITE = $(LINUX_SITE)
COREROUTER_INSTALLER_DL_SUBDIR = linux
COREROUTER_INSTALLER_LICENSE = GPL-2.0
COREROUTER_INSTALLER_LICENSE_FILES = COPYING
COREROUTER_INSTALLER_DEPENDENCIES = linux corerouter busybox host-kmod host-squashfs
COREROUTER_INSTALLER_INSTALL_TARGET = NO
COREROUTER_INSTALLER_INSTALL_IMAGES = YES
COREROUTER_INSTALLER_FRAGMENT = $(BR2_EXTERNAL_COREROUTER_PATH)/board/x86_64/installer.fragment
COREROUTER_INSTALLER_INIT = $(COREROUTER_OUT)/corerouter-init
COREROUTER_INSTALLER_MODULES = $(@D)/live-modules

# G1.6ze: the image's kernel patches. BR2_GLOBAL_PATCH_DIR gives a package
# only patches/<its own name>: without this hook the ISO's kernel was the
# plain tarball, and the live image showed the tunnels' catch-all devices
# (`gre0`, `sit0`…) that 0002 turns off. `cargo xtask os build` checks both
# trees' .applied_patches_list.
define COREROUTER_INSTALLER_APPLY_LINUX_PATCHES
	$(APPLY_PATCHES) $(@D) $(BR2_EXTERNAL_COREROUTER_PATH)/patches/linux \*.patch
endef
COREROUTER_INSTALLER_POST_PATCH_HOOKS += COREROUTER_INSTALLER_APPLY_LINUX_PATCHES

define COREROUTER_INSTALLER_CONFIGURE_CMDS
	cp $(LINUX_DIR)/.config $(@D)/.config
	cd $(@D) && KCONFIG_CONFIG=.config ./scripts/kconfig/merge_config.sh -m -O $(@D) \
		.config $(COREROUTER_INSTALLER_FRAGMENT)
	echo 'CONFIG_INITRAMFS_SOURCE="$(@D)/initramfs.list"' >> $(@D)/.config
	$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(@D) olddefconfig
endef

# The initramfs list: directories, /dev/console, the init and every
# library it needs (resolved in the image), the keys.
define COREROUTER_INSTALLER_INITRAMFS
	{ \
	for d in dev proc sys run tmp var etc etc/corerouter etc/corerouter/image-keys \
		usr usr/sbin lib sys/firmware sys/firmware/efi sys/firmware/efi/efivars \
		bin live newroot; do \
		echo "dir /$$d 0755 0 0"; done; \
	echo "nod /dev/console 0600 0 0 c 5 1"; \
	echo "slink /lib64 lib 0777 0 0"; \
	echo "file /usr/sbin/corerouter-init $(COREROUTER_INSTALLER_INIT) 0755 0 0"; \
	echo "slink /init /usr/sbin/corerouter-init 0777 0 0"; \
	echo "file /bin/busybox $$(readlink -f $(TARGET_DIR)/bin/busybox) 0755 0 0"; \
	for k in $(CR_SEAL_IMAGE_KEYS_DIR)/*.pub; do \
		echo "file /etc/corerouter/image-keys/$$(basename $$k) $$k 0644 0 0"; done; \
	libs="ld-linux-x86-64.so.2"; todo="$(COREROUTER_INSTALLER_INIT) $$(readlink -f $(TARGET_DIR)/bin/busybox)"; \
	while [ -n "$$todo" ]; do \
		set -- $$todo; f=$$1; shift; todo="$$*"; \
		for n in $$($(TARGET_READELF) -d $$f | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do \
			case " $$libs " in *" $$n "*) continue;; esac; \
			libs="$$libs $$n"; p=$$(readlink -f $(TARGET_DIR)/lib/$$n); \
			[ -f "$$p" ] || { echo "corerouter-installer: $$n not in the image" >&2; exit 1; }; \
			todo="$$todo $$p"; \
		done; \
	done; \
	for n in $$libs; do \
		echo "file /lib/$$n $$(readlink -f $(TARGET_DIR)/lib/$$n) 0755 0 0"; done; \
	} > $(@D)/initramfs.list
endef

# The modules, stripped, with their index and without the links to this
# machine's kernel tree. SOURCE_DATE_EPOCH (BR2_REPRODUCIBLE) sets the times;
# owners are fixed and one thread keeps the block order.
define COREROUTER_INSTALLER_LIVE_MODULES
	rm -rf $(COREROUTER_INSTALLER_MODULES)
	$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(@D) \
		INSTALL_MOD_PATH=$(COREROUTER_INSTALLER_MODULES) INSTALL_MOD_STRIP=1 \
		DEPMOD=$(HOST_DIR)/sbin/depmod modules_install
	rm -f $(COREROUTER_INSTALLER_MODULES)/lib/modules/*/build \
		$(COREROUTER_INSTALLER_MODULES)/lib/modules/*/source
	$(HOST_DIR)/bin/mksquashfs $(COREROUTER_INSTALLER_MODULES)/lib/modules \
		$(@D)/live-modules.img -noappend -all-root -no-xattrs -processors 1 \
		-comp zstd -Xcompression-level 19 -quiet
endef

# This package's per-package target dir holds a copy of corerouter's files
# from when it was configured; the final target is assembled from every
# per-package dir, and that stale copy would overwrite the fresh daemon and
# init (rebuilt every build). It installs nothing to the target: drop them.
define COREROUTER_INSTALLER_BUILD_CMDS
	rm -f $(TARGET_DIR)/usr/bin/corerouter-daemon $(TARGET_DIR)/usr/sbin/corerouter-init
	$(COREROUTER_INSTALLER_INITRAMFS)
	$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(@D) bzImage modules
	$(COREROUTER_INSTALLER_LIVE_MODULES)
endef

define COREROUTER_INSTALLER_INSTALL_IMAGES_CMDS
	$(INSTALL) -D -m 0644 $(@D)/arch/x86/boot/bzImage \
		$(BINARIES_DIR)/installer/EFI/BOOT/BOOTX64.EFI
	$(INSTALL) -D -m 0644 $(@D)/live-modules.img $(BINARIES_DIR)/live-modules.img
endef

$(eval $(generic-package))
