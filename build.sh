#!/bin/bash

# AIROS SDK Build Script
# Usage: ./build.sh <board_name> <release_version>
# Example: ./build.sh mt7621 1.0

# =============================================================================
# USER INPUT - MODIFY THESE PATHS AS NEEDED
# =============================================================================
SDK_DIR=/home/anjan/projects/airpro/mtk/mt7621/24.10/openwrt
OUTPUT_DIR=${PWD}/releases
# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

# Check arguments
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo ""
    echo "Usage: ./build.sh <board_name> <release_version>"
    echo "Example: ./build.sh mt7621 1.0"
    echo ""
    echo "Supported boards: mt7621, ipq5018"
    echo ""
    exit 1
fi

# Get parameters
BOARD_NAME=$1
RELEASE_VERSION=$2

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

elif [ "$BOARD_NAME" = "mt76" ]; then
    echo "Configuring for mt7621..."
    TARGET=ramips
    SUBTARGET=mt7621
    PROFILE=yuncore_ax820
    BUILD_DIR=${SDK_DIR}/build_dir/target-mipsel_24kc_musl
    FW_DIR=${SDK_DIR}/bin/targets/${TARGET}/${SUBTARGET}
    FW_FILE=openwrt-${TARGET}-${SUBTARGET}-${PROFILE}-squashfs-sysupgrade.bin
    rm -rf ${BUILD_DIR}/target-mipsel_24kc_musl/aircnms
    rm -rf ${BUILD_DIR}/target-mipsel_24kc_musl/linux-ramips_mt7621/airdpi
    rm -rf ${SDK_DIR}/packages/feeds/aircnms
    rm -rf ${SDK_DIR}/packages/feeds/airdpi
    cp -rf packages/aircnms $SDK_DIR/package/feeds/
    cp -rf packages/airdpi $SDK_DIR/package/feeds/
    cp -rf patches/mt7621/owrt-24.10/mac80211/999-airdpi-ops.patch $SDK_DIR/package/kernel/mac80211/patches/subsys/
    cp -rf packages/feeds/mt7621/owrt-24.10/mac80211/Makefile $SDK_DIR/package/kernel/mac80211/
    cp -rf packages/luci-app-airos/platform/mt76/luci/* ${SDK_DIR}/feeds/luci/
    cp -rf base-files/platform/mt7621/etc ${SDK_DIR}/package/base-files/files/
else
    echo "ERROR: Unknown board type: $BOARD_NAME"
    echo "Supported boards: mt7621, ipq5013"
    exit 1
fi

# =============================================================================
# COMMON OPERATIONS
# =============================================================================

# Copy common base files
# [ -d "../airos-sdk/base-files/common" ] && cp -rf ../airos-sdk/base-files/common/* package/base-files/files/

# Enter BUUILD directory
echo "Entering OpenWRT Directory: $SDK_DIR"
cd $SDK_DIR

# Create output directories
mkdir -p $OUTPUT_DIR/images $OUTPUT_DIR/logs

# =============================================================================
# BUILD PROCESS
# =============================================================================

echo "Running make defconfig..."
make defconfig

echo "Running make..."
make -j$(nproc) V=s 2>&1 | tee $OUTPUT_DIR/logs/build-${BUILD_DATETIME}.log

# =============================================================================
# COPY OUTPUT FILES
# =============================================================================

echo "Copying output files..."

cp ${FW_DIR}/${FW_FILE} $OUTPUT_DIR/images/$IMAGE_NAME.bin

# =============================================================================
# BUILD COMPLETE
# =============================================================================

echo "=========================================="
echo "Build completed successfully!"
echo "Image: $OUTPUT_DIR/images/$IMAGE_NAME.bin"
echo "Log: $OUTPUT_DIR/logs/build-${BUILD_DATETIME}.log"
echo "=========================================="
