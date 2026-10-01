# AirOS SDK Build & Configuration Guide

This guide explains how `airos-sdk` manages OpenWrt target configurations, handles package inclusions and exclusions, and builds firmware across different OpenWrt SDK environments.

---

## 1. Configuration Philosophy: `diffconfig` vs. Raw `.config`

OpenWrt generates a `~4,000-line` `.config` during build. However, checking in a raw `.config` into git is fragile because it contains machine-specific paths, toolchain cache flags, and kernel symbol hashes that break across different SDK releases.

Instead, `airos-sdk` uses OpenWrt's **`diffconfig`** mechanism:
- Minimal declarative profile (`~90 lines`) stored in [`config/profiles/<board>.config`](file:///home/airpro/projects/airpro/git/airos-sdk/config/profiles/).
- Contains **only explicit choices**:
  - Target architecture & board profile (`ramips / mt7621 / yuncore_ax820`).
  - Required packages (`aircnms`, `luci-theme-airui`, `hostapd-openssl`, etc.).
  - Explicitly disabled conflicting default packages.
- Running `make defconfig` on the SDK expands this minimal file into the full, dependency-resolved `.config`.

---

## 2. Managing Package Inclusions & Exclusions

### Enabling Packages
To include a package in the build, declare it in `config/profiles/<board>.config`:
```text
CONFIG_PACKAGE_aircnms=y
CONFIG_PACKAGE_hostapd-openssl=y
CONFIG_PACKAGE_luci-theme-airui=y
```

### Disabling Conflicting Packages & Themes
Certain OpenWrt targets enable conflicting packages or default themes by default (e.g. `wpad-basic-mbedtls`, default `hostapd`, `luci-theme-bootstrap`, `luci-theme-material`).

To ensure these conflicting packages and alternative themes are never selected:
1. Declare them as **not set** in `config/profiles/<board>.config`:
```text
# Explicitly disabled packages to prevent conflicts with hostapd-openssl
# CONFIG_PACKAGE_hostapd is not set
# CONFIG_PACKAGE_wpad-basic is not set
# CONFIG_PACKAGE_wpad-basic-mbedtls is not set
# CONFIG_PACKAGE_wpad-openssl is not set
# CONFIG_PACKAGE_wpad-mini is not set

# Explicitly disabled alternative themes to enforce AirUI branding & save flash
# CONFIG_PACKAGE_luci-theme-bootstrap is not set
# CONFIG_PACKAGE_luci-theme-material is not set
```

2. [`build.sh`](file:///home/airpro/projects/airpro/git/airos-sdk/build.sh) enforces these exclusions programmatically in `enable_wpa3_hostapd()` and `enable_airui_luci_packages()` right before `make defconfig` runs.

---

## 3. How to Update or Generate a New Profile

If you change packages via `make menuconfig` in the OpenWrt SDK and want to save the new configuration back into `airos-sdk`:

1. In the OpenWrt directory, run:
   ```bash
   ./scripts/diffconfig.sh > /path/to/airos-sdk/config/profiles/mtk-mt7621.config
   ```
2. Verify that your required packages and exclusions (`# CONFIG_PACKAGE_... is not set`) are present.
3. Commit the updated profile into git.

---

## 4. Building Firmware with a Brand New OpenWrt SDK

To build firmware from scratch using a fresh OpenWrt checkout or SDK:

### Step 1: Prepare the OpenWrt SDK
```bash
# Clone or unpack OpenWrt
git clone https://git.openwrt.org/openwrt/openwrt.git openwrt-sdk
cd openwrt-sdk

# Update standard OpenWrt feeds
./scripts/feeds update -a
./scripts/feeds install -a
```

### Step 2: Build Firmware Using `build.sh`
You can point `build.sh` to your OpenWrt directory using the `OPENWRT_SDK_DIR` environment variable:
```bash
cd /path/to/airos-sdk

# Build for MT7621 (version 1.0)
OPENWRT_SDK_DIR=/path/to/openwrt-sdk ./build.sh mt7621 1.0
```

### What `build.sh` does automatically:
1. Validates that the SDK directory exists.
2. Injects the board profile config (`config/profiles/mtk-mt7621.config` $\to$ `.config`).
3. Copies `aircnms` and AirUI LuCI overlays into the SDK feeds.
4. Enforces package exclusions (disabling conflicting `wpad`/`hostapd` packages).
5. Runs `make defconfig` to resolve all library and kernel dependencies.
6. Compiles the firmware image (`bin/targets/...`).
7. Packages the cloud firmware release (`releases/cloud/airos-mt7621-*.tar.gz`) with `manifest.json` and MD5 checksum.
