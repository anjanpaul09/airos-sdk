# AIROS SDK - OpenWrt Firmware Build System

A comprehensive build system for creating custom OpenWrt firmware images for various hardware platforms, specifically designed for AIROS's embedded devices.

## Overview

AIROS SDK provides a structured approach to building OpenWrt firmware with board-specific configurations, patches, and packages. The system supports multiple hardware platforms and allows for easy customization and maintenance.

## Directory Structure

```
airos-sdk/
├── build.sh                        # Main build script
├── README.md                       # This file
├── config/                         # Build configuration files
│   └── profiles/                   # Hardware-specific profiles
│       └── qca-ipq5018.conf       # IPQ5018 platform configuration
├── packages/                       # OpenWrt packages (to be populated)
│   ├── luci-app-airos/              # Web UI package
│   └── feeds/                     # External package feeds
├── bsp/                           # Board Support Package
│   ├── ipq5018/                  # IPQ5018 platform
│   │   ├── config/               # Platform configuration files
│   │   ├── drivers/              # Platform-specific drivers
│   │   ├── dts/                  # Device tree files
│   │   └── patches/              # Platform-specific patches
│   └── README                    # BSP documentation
├── patches/                       # Global patches
│   ├── drivers/                  # Driver patches
│   │   └── qca-wifi/            # QCA WiFi driver patches
│   │       └── ipq5018/         # IPQ5018-specific patches
│   ├── kernel/                   # Kernel patches
│   ├── openwrt/                  # OpenWrt core patches
│   │   └── ipq5018/             # IPQ5018-specific patches
│   └── packages/                 # Package patches
│       └── hostapd/              # Hostapd patches
│           └── ipq5018/          # IPQ5018-specific patches
├── base-files/                   # Base filesystem files
│   ├── common/                   # Common files
│   │   ├── etc/                  # Common configuration files
│   │   └── usr/                  # Common user files
│   └── platform/                 # Platform-specific files
│       └── ipq5018/              # IPQ5018-specific files
├── releases/                     # Release management
│   └── qcom/                     # Qualcomm platforms
│       └── ipq5013/              # IPQ5013 platform
│           └── xyz.simgle.img/   # Sample release images
└── output/                       # Build output directory (created during build)
    ├── images/                   # Firmware images
    ├── packages/                 # Package files
    └── logs/                     # Build logs
```

## Prerequisites

Before using AIROS SDK, ensure you have:

1. **QSDK Installation**: Download and install the appropriate QSDK for your target platform
2. **Toolchain**: Ensure the toolchain is properly installed and accessible
3. **Dependencies**: Install required build dependencies

## Configuration

### Environment Variables

Set the following environment variables before building:

```bash
export QSDK_PATH="/path/to/your/qsdk"           # Path to QSDK installation
export TOOLCHAIN_PATH="/path/to/toolchain"      # Path to toolchain
export OUTPUT_DIR="/path/to/output"             # Output directory
```

### Hardware Profiles

Hardware-specific configurations are stored in `config/profiles/`. Each profile contains:

- Platform-specific settings
- Kernel configuration
- Package selection
- Build flags and options

## Usage

### Basic Build Command

```bash
./build.sh <board_name> <release_version>
```

### Examples

```bash
# Build for IPQ5018 with version 1.0
./build.sh ipq5018 1.0

# Build for IPQ5013 with version 2.1
./build.sh ipq5013 2.1
```

### Environment Variables Required

Before building, set these environment variables:

```bash
export QSDK_PATH="/path/to/your/qsdk"
export TOOLCHAIN_PATH="/path/to/toolchain"
export OUTPUT_DIR="/path/to/output"
```

### Build Process

1. **Manual QSDK Entry**: Script enters the QSDK directory manually
2. **Board-Specific Operations**: Uses if/else if statements for different board types
3. **File Copying**: Copies board-specific files to the QSDK
4. **Patch Application**: Applies necessary patches
5. **Build Execution**: Executes the QSDK build process
6. **Output Generation**: Generates firmware images with timestamp

### Output Naming Convention

Generated images follow this naming pattern:
```
airos-<board_name>-<release_version>-<build_date>-<build_time>.bin
```

Example: `airos-ipq5018-1.0-20241215-143022.bin`

## Board-Specific Configuration

### IPQ5018 Platform

- **Profile**: `config/profiles/qca-ipq5018.conf`
- **BSP**: `bsp/ipq5018/`
- **Patches**: `patches/*/ipq5018/`
- **Base Files**: `base-files/platform/ipq5018/`

### Adding New Platforms

To add support for a new platform:

1. Create platform directory in `bsp/`
2. Add configuration profile in `config/profiles/`
3. Create platform-specific patches in `patches/`
4. Add base files in `base-files/platform/`
5. Update build script to handle the new platform

## Package Management

### Custom Packages

Place custom packages in the `packages/` directory:

- **luci-app-airos**: Web interface package

### External Feeds

External package feeds are managed in `packages/feeds/`:

- LuCI packages
- Third-party packages
- Community packages

## Patch Management

### Patch Organization

Patches are organized by component and platform:

- **Kernel patches**: `patches/kernel/`
- **Driver patches**: `patches/drivers/`
- **Package patches**: `patches/packages/`
- **OpenWrt patches**: `patches/openwrt/`

### Patch Naming Convention

Use descriptive names with version numbers:
```
001-descriptive-patch-name.patch
002-another-patch.patch
```

## Development Workflow

1. **Setup Environment**: Configure paths and dependencies
2. **Select Board**: Choose target hardware platform
3. **Customize Configuration**: Modify profiles and base files
4. **Apply Patches**: Add necessary patches
5. **Build Firmware**: Execute build process
6. **Test Images**: Validate generated firmware
7. **Release**: Package and distribute firmware

## Troubleshooting

### Common Issues

1. **Path Configuration**: Ensure all paths are correctly set
2. **Dependencies**: Check that all required tools are installed
3. **Permissions**: Verify write permissions for output directories
4. **Disk Space**: Ensure sufficient space for build process

### Build Logs

Build logs are stored in `output/logs/` for debugging and analysis.

## Contributing

1. Follow the established directory structure
2. Use consistent naming conventions
3. Document any new platforms or features
4. Test builds before submitting changes

## Support

For support and questions:
- Check build logs in `output/logs/`
- Review configuration files
- Consult platform-specific documentation

## License

[Add your license information here]

---

**Note**: This build system is designed to work with AIROS's specific hardware requirements and may need customization for other platforms.
