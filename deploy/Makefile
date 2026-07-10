# OpenWrt / RutOS SDK package recipe for portcullis (TDD §10).
#
# Builds the Rust daemon for the RUTM11 (ramips/mt7621, mipsel-unknown-linux-musl)
# and packages it as an .ipk with its procd init, UCI config, capabilities file,
# and first-boot bootstrap.
#
# Usage (inside an OpenWrt/RutOS SDK checkout):
#   ln -s <this-repo> package/portcullis        # or copy; expects ../.. = repo root
#   ./scripts/feeds update -a && ./scripts/feeds install -a
#   make package/portcullis/compile V=s
#
# NOTE: mipsel-musl is a Rust tier-3 target (no prebuilt std). The build below
# uses `-Z build-std` on nightly, linking against the SDK's musl toolchain
# (TDD §5.3). If the `rust` feed is present, prefer its rust-package.mk instead.

include $(TOPDIR)/rules.mk

PKG_NAME:=portcullis
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=The portcullis authors
PKG_LICENSE:=MIT OR Apache-2.0

# The crate sources live one level above deploy/ (the workspace root).
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

RUST_TARGET:=mipsel-unknown-linux-musl

define Package/portcullis
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Per-store captive-portal edge enforcement engine
  URL:=https://github.com/aupv9/portcullis-rust
  # Runtime deps: the nftables backend + dnsmasq nftset support (§5.2, §7.3),
  # plus the ZTP first-boot claim agent's tools (curl for the HTTPS claim POST,
  # openssl-util for the HMAC signature, ca-bundle for TLS trust) so a golden
  # image can self-enroll with NO opkg/internet at install time.
  DEPENDS:=+nftables +kmod-nft-core +kmod-nft-nat +dnsmasq-full +curl +ca-bundle +openssl-util
endef

define Package/portcullis/description
  portcullis holds the internet gate shut until the WiFi Hub control plane
  authorizes a client, then enforces, meters, and expires that grant. Owns one
  nftables table (inet wifihub); dials the control plane outbound over an
  mTLS gRPC stream (CGNAT-safe). RAM-only state; CAP_NET_ADMIN, non-root.
endef

# Copy the workspace into the build dir (deploy/.. == repo root).
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/../. $(PKG_BUILD_DIR)/src/
endef

# Cross-compile the engine binary. The SDK provides the musl sysroot + linker;
# we point cargo at it and build std from source for the tier-3 target.
define Build/Compile
	cd $(PKG_BUILD_DIR)/src && \
	CARGO_HOME=$(PKG_BUILD_DIR)/cargo-home \
	CARGO_BUILD_TARGET=$(RUST_TARGET) \
	CARGO_TARGET_$(shell echo $(RUST_TARGET) | tr 'a-z-' 'A-Z_')_LINKER=$(TARGET_CC) \
	$(CARGO_VARS) \
	cargo +nightly build --release \
		-Z build-std=std,panic_abort \
		--target $(RUST_TARGET) \
		-p portcullis-engined
endef

define Package/portcullis/conffiles
/etc/config/portcullis
/etc/portcullis/bootstrap.conf
endef

define Package/portcullis/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/src/target/$(RUST_TARGET)/release/portcullis \
		$(1)/usr/sbin/portcullis

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/portcullis.init $(1)/etc/init.d/portcullis
	# ZTP first-boot claim agent (self-hosted zero-touch onboarding).
	$(INSTALL_BIN) $(CURDIR)/portcullis-enroll.init $(1)/etc/init.d/portcullis-enroll

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/config/portcullis $(1)/etc/config/portcullis

	# ZTP batch bootstrap config (CP domain + fleet secret; conffile, per-batch).
	$(INSTALL_DIR) $(1)/etc/portcullis
	$(INSTALL_CONF) $(CURDIR)/config/bootstrap.conf $(1)/etc/portcullis/bootstrap.conf

	$(INSTALL_DIR) $(1)/etc/capabilities
	$(INSTALL_DATA) $(CURDIR)/capabilities/portcullis.json $(1)/etc/capabilities/portcullis.json

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(CURDIR)/uci-defaults/99-portcullis $(1)/etc/uci-defaults/99-portcullis
	$(INSTALL_BIN) $(CURDIR)/uci-defaults/99-portcullis-enroll $(1)/etc/uci-defaults/99-portcullis-enroll
endef

$(eval $(call BuildPackage,portcullis))
