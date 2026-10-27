################################################################################
#
# corerouter: corerouter-daemon + corerouter-init from this workspace (G1.6a)
#
# No download: the source is the workspace around os/. cargo comes from the
# host (rustup, the toolchain in rust-toolchain.toml), runs --locked
# --offline (crates already in ~/.cargo) and links with the Buildroot
# toolchain, so the binaries use the image's glibc and the C bits (ring)
# are compiled by the same gcc as the rest of the image.
#
################################################################################

COREROUTER_SRC_DIR = $(realpath $(BR2_EXTERNAL_COREROUTER_PATH)/..)
COREROUTER_LICENSE = AGPL-3.0-or-later
COREROUTER_LICENSE_FILES = LICENSE
COREROUTER_CARGO ?= cargo
# Outside $(@D): `corerouter-rebuild` stays incremental (warm: seconds).
COREROUTER_CARGO_TARGET_DIR ?= $(BASE_DIR)/cargo-target
COREROUTER_TRIPLE = x86_64-unknown-linux-gnu
COREROUTER_OUT = $(COREROUTER_CARGO_TARGET_DIR)/$(COREROUTER_TRIPLE)/release

# Reproducible: no absolute paths of this machine in the binaries, the
# timestamp Buildroot fixes for the whole image.
COREROUTER_CARGO_ENV = \
	CARGO_TARGET_DIR="$(COREROUTER_CARGO_TARGET_DIR)" \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$(TARGET_CC)" \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="--remap-path-prefix=$(COREROUTER_SRC_DIR)=/corerouter --remap-path-prefix=$(HOME)=/home" \
	CC_x86_64_unknown_linux_gnu="$(TARGET_CC)" \
	AR_x86_64_unknown_linux_gnu="$(TARGET_AR)" \
	CFLAGS_x86_64_unknown_linux_gnu="$(TARGET_CFLAGS)" \
	SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)"

define COREROUTER_BUILD_CMDS
	cd $(COREROUTER_SRC_DIR) && $(COREROUTER_CARGO_ENV) $(COREROUTER_CARGO) build \
		--release --locked --offline -j $(PARALLEL_JOBS) \
		--target $(COREROUTER_TRIPLE) \
		-p corerouter-daemon -p corerouter-init
endef

define COREROUTER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(COREROUTER_OUT)/corerouter-daemon $(TARGET_DIR)/usr/bin/corerouter-daemon
	$(INSTALL) -D -m 0755 $(COREROUTER_OUT)/corerouter-init $(TARGET_DIR)/usr/sbin/corerouter-init
endef

$(eval $(generic-package))
