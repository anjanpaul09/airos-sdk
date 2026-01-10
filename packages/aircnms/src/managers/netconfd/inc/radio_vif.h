#include <stdbool.h>

#define ENCRYPT_TYPE_MAX_LEN 16

enum {
    AIR_DIR_UPLINK,
    AIR_DIR_DOWNLINK,
    AIR_DIR_MAX
};

struct airpro_mgr_wlan_vap_params {
    char wds[8];
    char dhcppoolname[32]; //ui
    char hide_ssid[8];
    char isolate[8];
    char ssid[32];
    char opmode[10];
    char encryption[16];
    char key[16];
    char server_name[32];
    char server_ip[64];
    char auth_port[16];
    char acct_port[16];
    char secret_key[64];
    char wifi_device[8]; //wifi0, wifi1, wifi2
    char network[16];
    bool is_auth;
    char auth_url[512];
    bool is_uprate;
    int  uprate;
    bool is_downrate;
    int  downrate;
    bool is_wlan_uprate;
    int  wlan_uprate;
    bool is_wlan_downrate;
    int  wlan_downrate;
    char enable[8];
    char mobility_id[12];
    char is_deleted[8];
    char qos_enable[12];
    char forward_type[32];
    char wlan_qos_enable[12];
    char band_select_enable[12];
    char record_id[12];
    char vlan_id[8];
    char ifname[8];
    char macfilter[8];
    char maclist[512];
    int  status; // cloud: 1=add, 2=edit, 3=del
    char device[8];
    char disabled[8];
    char prior5g[4];
};

struct airpro_mgr_wlan_radio_params {
    char channel[8];
    char disabled[8];
    char txpower[8];
    char mode[16];
    char country[8];
    char record_id[12];
    char max_sta[8];
    char channel_width[8];
    char user_limit[8];
    char bw[8];
    char radio_type[8];
    char hwmode[16];
    char htmode[16];
    int radio_index;
    int num_vaps;
    int status; // cloud: 0=add, 1=edit
};

struct airpro_mgr_get_all_uci_section_names {
    int num_entry;
    char sec_name[20][20];
};

typedef struct
{
    int n_radio;
    struct airpro_mgr_wlan_radio_params radio_param[2]; //set num radio macro
} radio_record_t;

typedef struct
{
    int n_vif;
    struct airpro_mgr_wlan_vap_params vif_param[16]; //set num vif macro
} vif_record_t;


typedef struct
{
    char ipaddr[32];
    char netmask[32];
} nat_config_t;
