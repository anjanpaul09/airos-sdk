#include "ds.h"
#include "../../../pbuf/aircnms_stats.pb-c.h"


struct wlan_vif_stats {
	char radio[8];
	char ssid[32];
	uint32_t num_sta;
	long uplink_mb;
	long downlink_mb;
};

struct wlan_radio_stats {
	char band[8];
	char ssid[32];
	uint8_t channel;
	uint8_t txpower;
	uint8_t channel_utilization;
};

typedef struct
{
    int n_vif;
    struct wlan_vif_stats vif[32]; //set num vif macro
	int n_radio;
    struct wlan_radio_stats radio[4]; //set num vif macro
} dpp_vif_record_t;


typedef struct
{
    dpp_vif_record_t                record;
    uint64_t                        timestamp_ms;
} dpp_vif_report_data_t;
