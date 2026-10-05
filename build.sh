#!/bin/bash

# AIROS SDK Build Script
# Usage: ./build.sh <board_name> <release_version>
# Example: ./build.sh mt7621 1.0

# =============================================================================
# USER INPUT - MODIFY THESE PATHS AS NEEDED
# =============================================================================
SDK_DIR="${OPENWRT_SDK_DIR:-/home/airpro/projects/airpro/mtk/mt7621/sdk/openwrt}"
OUTPUT_DIR=${PWD}/releases
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AIROS_LUCI_OVERLAY_DIR="${SCRIPT_DIR}/packages/luci-app-airos/platform/mt76/luci"
# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

install_airui_luci_overlay() {
    echo "Installing AirUI theme and LuCI pages..."

    if [ ! -d "${AIROS_LUCI_OVERLAY_DIR}/themes/luci-theme-airui" ]; then
        echo "ERROR: Missing AirUI theme: ${AIROS_LUCI_OVERLAY_DIR}/themes/luci-theme-airui"
        exit 1
    fi

    if [ ! -d "${AIROS_LUCI_OVERLAY_DIR}/modules/luci-mod-status" ]; then
        echo "ERROR: Missing AirUI status pages: ${AIROS_LUCI_OVERLAY_DIR}/modules/luci-mod-status"
        exit 1
    fi

    for package_makefile in \
        "${AIROS_LUCI_OVERLAY_DIR}/themes/luci-theme-airui/Makefile" \
        "${AIROS_LUCI_OVERLAY_DIR}/modules/luci-app-airpro-security/Makefile" \
        "${AIROS_LUCI_OVERLAY_DIR}/modules/luci-app-airpro-advanced/Makefile"
    do
        if [ ! -f "${package_makefile}" ]; then
            echo "ERROR: Missing LuCI package definition: ${package_makefile}"
            exit 1
        fi
    done

    mkdir -p "${SDK_DIR}/feeds/luci"
    cp -rf "${AIROS_LUCI_OVERLAY_DIR}/." "${SDK_DIR}/feeds/luci/"

    mkdir -p "${SDK_DIR}/package/feeds/luci"
    ln -sfn ../../../feeds/luci/themes/luci-theme-airui \
        "${SDK_DIR}/package/feeds/luci/luci-theme-airui"
    ln -sfn ../../../feeds/luci/modules/luci-app-airpro-security \
        "${SDK_DIR}/package/feeds/luci/luci-app-airpro-security"
    ln -sfn ../../../feeds/luci/modules/luci-app-airpro-advanced \
        "${SDK_DIR}/package/feeds/luci/luci-app-airpro-advanced"

    rm -rf \
        "${SDK_DIR}"/build_dir/target-*/luci-mod-status \
        "${SDK_DIR}"/build_dir/target-*/luci-mod-network \
        "${SDK_DIR}"/build_dir/target-*/luci-app-airpro-security \
        "${SDK_DIR}"/build_dir/target-*/luci-app-airpro-advanced \
        "${SDK_DIR}"/build_dir/target-*/luci-theme-airui \
        "${SDK_DIR}"/build_dir/target-*/luci-mod-system \
        "${SDK_DIR}"/build_dir/target-*/luci-app-package-manager

    echo "AirUI overlay installed into ${SDK_DIR}/feeds/luci"
}

enable_airui_luci_packages() {
    echo "Selecting AirUI LuCI packages..."

    touch .config

    # Explicitly disable alternative themes to enforce AirUI branding & save flash space
    for theme in luci-theme-bootstrap luci-theme-material; do
        sed -i "/^CONFIG_PACKAGE_${theme}=/d" .config
        if ! grep -q "^# CONFIG_PACKAGE_${theme} is not set" .config; then
            echo "# CONFIG_PACKAGE_${theme} is not set" >> .config
        fi
    done

    # Explicitly disable stock system and package-manager to keep Administration menu clean
    for pkg in luci-mod-admin-full luci-mod-system luci-app-package-manager; do
        sed -i "/^CONFIG_PACKAGE_${pkg}=/d" .config
        if ! grep -q "^# CONFIG_PACKAGE_${pkg} is not set" .config; then
            echo "# CONFIG_PACKAGE_${pkg} is not set" >> .config
        fi
    done

    for package in \
        luci-base \
        luci-mod-status \
        luci-mod-network \
        luci-app-airpro-security \
        luci-app-airpro-advanced \
        luci-theme-airui
    do
        if grep -q "^CONFIG_PACKAGE_${package}=" .config; then
            sed -i "s/^CONFIG_PACKAGE_${package}=.*/CONFIG_PACKAGE_${package}=y/" .config
        elif grep -q "^# CONFIG_PACKAGE_${package} is not set" .config; then
            sed -i "s/^# CONFIG_PACKAGE_${package} is not set/CONFIG_PACKAGE_${package}=y/" .config
        else
            echo "CONFIG_PACKAGE_${package}=y" >> .config
        fi
    done
}

enable_wpa3_hostapd() {
    echo "Selecting the OpenSSL hostapd variant and disabling conflicts..."

    touch .config

    # Explicitly disable all conflicting hostapd/wpad variants
    for pkg in hostapd wpad-openssl wpad-basic wpad-basic-mbedtls wpad-mini; do
        sed -i "/^CONFIG_PACKAGE_${pkg}=/d" .config
        if ! grep -q "^# CONFIG_PACKAGE_${pkg} is not set" .config; then
            echo "# CONFIG_PACKAGE_${pkg} is not set" >> .config
        fi
    done

    sed -i '/^CONFIG_PACKAGE_hostapd-openssl=/d' .config
    sed -i '/^# CONFIG_PACKAGE_hostapd-openssl is not set/d' .config
    echo 'CONFIG_PACKAGE_hostapd-openssl=y' >> .config
}

ensure_diagnostic_packages() {
    echo "Ensuring diagnostic packages: iperf3, tcpdump, libpcap..."

    if [ ! -x "./scripts/feeds" ]; then
        echo "ERROR: ./scripts/feeds not found or not executable"
        return 1
    fi

    if [ ! -e "package/feeds/packages/iperf3" ]; then
        echo "iperf3 package link missing; ensuring packages feed is available..."

        ./scripts/feeds update packages || {
            echo "ERROR: Failed to update packages feed"
            return 1
        }

        ./scripts/feeds install iperf3 || {
            echo "ERROR: Failed to install iperf3 from packages feed"
            return 1
        }
    fi

    touch .config

    sed -i \
        -e '/^CONFIG_PACKAGE_tcpdump-mini=/d' \
        -e '/^# CONFIG_PACKAGE_tcpdump-mini is not set/d' \
        .config

    echo '# CONFIG_PACKAGE_tcpdump-mini is not set' >> .config

    for pkg in tcpdump libpcap iperf3; do
        sed -i \
            -e "/^CONFIG_PACKAGE_${pkg}=/d" \
            -e "/^# CONFIG_PACKAGE_${pkg} is not set/d" \
            .config

        echo "CONFIG_PACKAGE_${pkg}=y" >> .config
    done
}

verify_diagnostic_packages() {
    echo "Verifying diagnostic packages in .config..."

    for pkg in tcpdump libpcap iperf3; do
        if ! grep -q "^CONFIG_PACKAGE_${pkg}=y$" .config; then
            echo "ERROR: CONFIG_PACKAGE_${pkg} was removed by Kconfig"
            return 1
        fi
    done

    echo "Diagnostic packages successfully verified in .config"
}


# Check arguments
if [ $# -lt 1 ] || [ $# -gt 3 ]; then
    echo ""
    echo "Usage: ./build.sh <board_name> [release_version] [product_model]"
    echo "Example: ./build.sh mt7621 1.2 AP520"
    echo ""
    echo "Supported boards: mt7621, ipq5018"
    echo ""
    exit 1
fi

# Get parameters
BOARD_NAME=$1
RELEASE_VERSION=${2:-"1.2"}
PRODUCT_MODEL=${3:-"AP520"}
PLATFORM_NAME="airos"

# Generate timestamp and image name
BUILD_DATE=$(date +"%Y%m%d")
BUILD_TIME=$(date +"%H%M%S")
BUILD_DATETIME="${BUILD_DATE}-${BUILD_TIME}"
IMAGE_NAME="airos-${BOARD_NAME}-${RELEASE_VERSION}-${BUILD_DATETIME}"
FW_DIR=""

# Display build info
echo "=========================================="
echo "AIROS SDK Build"
echo "=========================================="
echo "Board: $BOARD_NAME"
echo "Model: $PRODUCT_MODEL"
echo "Platform: $PLATFORM_NAME"
echo "Version: $RELEASE_VERSION"
echo "Date: $BUILD_DATE"
echo "Time: $BUILD_TIME"
echo "Image: $IMAGE_NAME"
echo "=========================================="


# =============================================================================
# BOARD-SPECIFIC CONFIGURATION
# =============================================================================

if [ "$BOARD_NAME" = "ipq5018" ]; then
    echo "Configuring for IPQ5018..."
    
    # Copy BSP files
    [ -d "../airos-sdk/bsp/mt7621/drivers" ] && cp -rf ../airos-sdk/bsp/mt7621/drivers/* package/kernel/
    [ -d "../airos-sdk/bsp/mt7621/dts" ] && cp -rf ../airos-sdk/bsp/mt7621/dts/* target/linux/qca/
    [ -d "../airos-sdk/bsp/mt7621/config" ] && cp -rf ../airos-sdk/bsp/mt7621/config/* target/linux/qca/
    
    # Copy base files
    [ -d "../airos-sdk/base-files/platform/mt7621" ] && cp -rf ../airos-sdk/base-files/platform/mt7621/* package/base-files/files/
    
    # Apply patches
    [ -d "../airos-sdk/patches/kernel/mt7621" ] && for patch in ../airos-sdk/patches/kernel/mt7621/*.patch; do [ -f "$patch" ] && echo "Applying: $(basename "$patch")"; done
    [ -d "../airos-sdk/patches/drivers/qca-wifi/mt7621" ] && for patch in ../airos-sdk/patches/drivers/qca-wifi/mt7621/*.patch; do [ -f "$patch" ] && echo "Applying: $(basename "$patch")"; done
    [ -d "../airos-sdk/patches/packages/hostapd/mt7621" ] && for patch in ../airos-sdk/patches/packages/hostapd/mt7621/*.patch; do [ -f "$patch" ] && echo "Applying: $(basename "$patch")"; done
    [ -d "../airos-sdk/patches/openwrt/mt7621" ] && for patch in ../airos-sdk/patches/openwrt/mt7621/*.patch; do [ -f "$patch" ] && echo "Applying: $(basename "$patch")"; done
    
    # Copy packages and load config
    [ -d "../airos-sdk/packages" ] && cp -rf ../airos-sdk/packages/* package/
    [ -f "../airos-sdk/config/profiles/qca-mt7621.conf" ] && cp ../airos-sdk/config/profiles/qca-mt7621.conf .config

elif [ "$BOARD_NAME" = "mt76" ] || [ "$BOARD_NAME" = "mt7621" ]; then
    echo "Configuring for mt7621..."
    TARGET=ramips
    SUBTARGET=mt7621
    PROFILE=yuncore_ax820
    BUILD_DIR=${SDK_DIR}/build_dir/target-mipsel_24kc_musl
    FW_DIR=${SDK_DIR}/bin/targets/${TARGET}/${SUBTARGET}
    FW_FILE=openwrt-${TARGET}-${SUBTARGET}-${PROFILE}-squashfs-sysupgrade.bin
    rm -rf "${SDK_DIR}"/build_dir/target-*/aircnms*
    rm -rf "${SDK_DIR}"/build_dir/target-*/linux-*/airdpi*
    rm -rf "${SDK_DIR}"/package/feeds/aircnms
    rm -rf "${SDK_DIR}"/package/feeds/airdpi
    
    echo "${IMAGE_NAME}" > base-files/platform/mt7621/etc/version
    
    mkdir -p base-files/platform/mt7621/etc/config
    cat << EOF > base-files/platform/mt7621/etc/config/version
config version 'version'
	option version '${RELEASE_VERSION}'
	option timestamp '${BUILD_DATE}'
	option model '${PRODUCT_MODEL}'
	option platform '${PLATFORM_NAME}'
EOF

    # Apply board profile configuration to SDK
    PROFILE_CONFIG="${SCRIPT_DIR}/config/profiles/mtk-mt7621.config"
    if [ -f "${PROFILE_CONFIG}" ]; then
        echo "Applying board profile configuration: ${PROFILE_CONFIG} -> ${SDK_DIR}/.config"
        cp -f "${PROFILE_CONFIG}" "${SDK_DIR}/.config"
    else
        echo "WARNING: Board profile config not found at ${PROFILE_CONFIG}"
    fi

    cp -rf packages/aircnms $SDK_DIR/package/feeds/
    install_airui_luci_overlay
    cp -rf base-files/platform/mt7621/etc ${SDK_DIR}/package/base-files/files/
else
    echo "ERROR: Unknown board type: $BOARD_NAME"
    echo "Supported boards: mt7621, ipq5013"
    exit 1
fi

# =============================================================================
# COMMON OPERATIONS
# =============================================================================

# Validate OpenWrt SDK directory
if [ ! -d "${SDK_DIR}" ]; then
    echo "ERROR: OpenWrt SDK directory not found: ${SDK_DIR}"
    echo "Please set the OPENWRT_SDK_DIR environment variable or adjust SDK_DIR in build.sh."
    exit 1
fi

# Enter BUILD directory
echo "Entering OpenWRT Directory: $SDK_DIR"
cd $SDK_DIR

# Create output directories
mkdir -p $OUTPUT_DIR/images $OUTPUT_DIR/logs $OUTPUT_DIR/cloud

if [ "$BOARD_NAME" = "mt76" ] || [ "$BOARD_NAME" = "mt7621" ]; then
    enable_airui_luci_packages
    enable_wpa3_hostapd
    ensure_diagnostic_packages || exit 1
fi

# =============================================================================
# BUILD PROCESS
# =============================================================================

echo "Running make defconfig..."
make defconfig

if [ "$BOARD_NAME" = "mt76" ] || [ "$BOARD_NAME" = "mt7621" ]; then
    verify_diagnostic_packages || exit 1
fi

echo "Running make..."
make -j$(nproc) V=s 2>&1 | tee $OUTPUT_DIR/logs/build-${BUILD_DATETIME}.log

# =============================================================================
# COPY OUTPUT FILES
# =============================================================================

echo "Copying output files..."

RAW_IMAGE_PATH="$OUTPUT_DIR/images/$IMAGE_NAME.bin"
CLOUD_PACKAGE_PATH="$OUTPUT_DIR/cloud/$IMAGE_NAME.tar.gz"
CLOUD_WORK_DIR="$OUTPUT_DIR/cloud/.work-$IMAGE_NAME"

cp ${FW_DIR}/${FW_FILE} "$RAW_IMAGE_PATH"

echo "Creating cloud firmware package..."
rm -rf "$CLOUD_WORK_DIR"
mkdir -p "$CLOUD_WORK_DIR/$IMAGE_NAME"
cp "$RAW_IMAGE_PATH" "$CLOUD_WORK_DIR/$IMAGE_NAME/$IMAGE_NAME.bin"
(
    cd "$CLOUD_WORK_DIR/$IMAGE_NAME"
    md5sum "$IMAGE_NAME.bin" | awk '{print $1}' > md5sum
    cat > manifest.json <<EOF
{
  "name": "$IMAGE_NAME",
  "board": "$BOARD_NAME",
  "version": "$RELEASE_VERSION",
  "build_date": "$BUILD_DATE",
  "build_time": "$BUILD_TIME",
  "image": "$IMAGE_NAME.bin",
  "checksum_type": "md5",
  "checksum": "$(cat md5sum)"
}
EOF
)
tar -C "$CLOUD_WORK_DIR" -czf "$CLOUD_PACKAGE_PATH" "$IMAGE_NAME"
rm -rf "$CLOUD_WORK_DIR"

# =============================================================================
# BUILD COMPLETE
# =============================================================================

echo "=========================================="
echo "Build completed successfully!"
echo "Image: $RAW_IMAGE_PATH"
echo "Cloud package: $CLOUD_PACKAGE_PATH"
echo "Log: $OUTPUT_DIR/logs/build-${BUILD_DATETIME}.log"
echo "=========================================="
