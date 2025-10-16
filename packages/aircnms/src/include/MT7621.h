#define CONFIG_PLATFORM_IS_MTK 1
#define CONFIG_TARGET_PATH_OVSDB_SOCK "/var/run/db.sock"
#define CONFIG_INSTALL_PREFIX "/usr/aircnms"
#define CONFIG_TARGET_NAME "MT7621"
#define CONFIG_TARGET_LAN_BRIDGE_NAME "br-lan"
#define CONFIG_HOSTAP_WPA_SUPPLICANT_GLOBAL_PATH "/var/run/wpa_supplicant/global"
#define CONFIG_TARGET_PATH_CERT "/var/certs"
#define CONFIG_TARGET_PATH_CERT_CA "ca.pem"
#define CONFIG_TARGET_PATH_PRIV_CERT "client.pem"
#define CONFIG_TARGET_PATH_PRIV_KEY "client_dec.key"
#define CONFIG_TARGET_OPENSYNC_CAFILE "ca.pem"
#define CONFIG_TARGET_PATH_SCRIPTS "/usr/aircnms/bin"

#define SM_VIF_REPORTING_INTERVAL         5
#define SM_DEVICE_REPORTING_INTERVAL      30
#define SM_CLIENT_REPORTING_INTERVAL      8
#define SM_NEIGHBOR_REPORTING_INTERVAL    1  //updated
#define SM_NEIGHBOR_REPORTING_COUNT       1  //updated

#ifdef CONFIG_PLATFORM_MTK_JEDI
#define CONFIG_MAC80211_WIPHY_PREFIX "ra"
#define CONFIG_MAC80211_WIPHY_PATH "/sys/class/net"
#define SM_BASE_RADIO_2G "ra0"
#define SM_BASE_RADIO_5G "rax1"
#define SM_BASE_INTERFACE_2G "ra0"
#define SM_BASE_INTERFACE_5G "rax0"
#endif

#ifdef CONFIG_PLATFORM_MTK
#define CONFIG_MAC80211_WIPHY_PREFIX "phy"
#define CONFIG_MAC80211_WIPHY_PATH "/sys/class/ieee80211"
#define SM_BASE_RADIO_2G "phy0"
#define SM_BASE_RADIO_5G "phy1"
#define SM_BASE_INTERFACE_2G "phy0-ap0"
#define SM_BASE_INTERFACE_5G "phy1-ap0"
#endif

#define DM_FW_UPGRADE_URL "http://69.30.254.180:8002/api/v1/file/download/"

