include $(sort $(wildcard $(BR2_EXTERNAL_COREROUTER_PATH)/package/*/*.mk))

# G1.6c: FRR selects readline, and nftables then builds `nft -i` against
# it. The router does not need an interactive nft (nor readline/ncurses in
# the image, post-build.sh): configure's last --with/--without wins.
NFTABLES_CONF_OPTS += --without-cli
NFTABLES_LIBS := $(filter-out -lncurses,$(NFTABLES_LIBS))
