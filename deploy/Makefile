# OpenWrt / RutOS SDK package recipe for portcullis (TDD §10).
#
# Builds the Rust daemon for the ramips/mipsel-unknown-linux-musl routers and
# packages it as an .ipk with its procd init, UCI config, capabilities file, and
# first-boot bootstrap. Two devices are in scope, same target triple & arch
# string (mipsel_24kc), different SDK subtarget:
#   - RUTM11 (MT7621, ramips/mt7621)  — NAND, roomy.
#   - RUT200 (MT7628, ramips/mt76x8)  — **16 MB SPI NOR flash, 128 MB RAM** (tight).
#
# Usage (inside an OpenWrt/RutOS SDK checkout):
#   ln -s <this-repo> package/portcullis        # or copy; expects ../.. = repo root
#   ./scripts/feeds update -a && ./scripts/feeds install -a
#   make package/portcullis/compile V=s
#
# Size for the RUT200 flash budget (§14): built with the `release-min` cargo
# profile (panic=abort) + `-Z build-std-features=panic_immediate_abort` (drops the
# panic-format machinery — a big win on MIPS), then optionally UPX-packed so the
# on-flash binary stays ~1 MB regardless of the overlay filesystem's own
# compression. Set PORTCULLIS_UPX=0 to skip packing (e.g. roomy RUTM11 NAND).
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
# Size-first cargo profile (see root Cargo.toml [profile.release-min]).
RUST_PROFILE:=release-min
# UPX-pack the binary by default to fit the RUT200's 16 MB flash; PORTCULLIS_UPX=0
# disables it (the packed binary decompresses into RAM at start — fine on 128 MB).
PORTCULLIS_UPX?=1

define Package/portcullis
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Per-store captive-portal edge enforcement engine
  URL:=https://github.com/aupv9/portcullis-rust
  # Runtime deps: the nftables backend + dnsmasq nftset support (§5.2, §7.3).
  DEPENDS:=+nftables +kmod-nft-core +kmod-nft-nat +dnsmasq-full
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
#   --profile release-min                       size-first profile (panic=abort)
#   -Z build-std=std,panic_abort                tier-3 has no prebuilt std
#   -Z build-std-features=panic_immediate_abort drop panic-format machinery (MIPS win)
define Build/Compile
	cd $(PKG_BUILD_DIR)/src && \
	CARGO_HOME=$(PKG_BUILD_DIR)/cargo-home \
	CARGO_BUILD_TARGET=$(RUST_TARGET) \
	CARGO_TARGET_$(shell echo $(RUST_TARGET) | tr 'a-z-' 'A-Z_')_LINKER=$(TARGET_CC) \
	$(CARGO_VARS) \
	cargo +nightly build --profile $(RUST_PROFILE) \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort \
		--target $(RUST_TARGET) \
		-p portcullis-engined
	# Optional UPX pack to fit the RUT200's 16 MB flash. Best-effort: warn (don't
	# fail the build) if the host lacks `upx`, so the RUTM11 path still packages.
	@if [ "$(PORTCULLIS_UPX)" = "1" ]; then \
		BIN=$(PKG_BUILD_DIR)/src/target/$(RUST_TARGET)/$(RUST_PROFILE)/portcullis; \
		if command -v upx >/dev/null 2>&1; then \
			echo ">> UPX-packing $$BIN"; \
			upx -9 --lzma --no-progress "$$BIN" || upx -9 --no-progress "$$BIN"; \
		else \
			echo ">> WARNING: upx not found on build host — skipping compression."; \
			echo ">>          install 'upx' (or 'upx-ucl') or set PORTCULLIS_UPX=0 to silence."; \
		fi; \
	fi
endef

define Package/portcullis/conffiles
/etc/config/portcullis
endef

define Package/portcullis/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/src/target/$(RUST_TARGET)/$(RUST_PROFILE)/portcullis \
		$(1)/usr/sbin/portcullis

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/portcullis.init $(1)/etc/init.d/portcullis

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/config/portcullis $(1)/etc/config/portcullis

	$(INSTALL_DIR) $(1)/etc/capabilities
	$(INSTALL_DATA) $(CURDIR)/capabilities/portcullis.json $(1)/etc/capabilities/portcullis.json

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(CURDIR)/uci-defaults/99-portcullis $(1)/etc/uci-defaults/99-portcullis
endef

$(eval $(call BuildPackage,portcullis))
