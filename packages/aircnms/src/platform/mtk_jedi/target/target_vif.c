#include "dpp_vif_stats.h"

#define MAX_NUM_RADIO 2
#define MAX_NUM_VIF   8 

bool jedi_stats_vif_get(dpp_vif_record_t* report_ctx) 
{
    bool rc;

    //report_ctx->timestamp_ms = get_current_timestamp_ms();

    report_ctx->n_vif = MAX_NUM_VIF;  

    // 1st vif
    sprintf(report_ctx->vif[0].radio, "%s", "BAND2G");
    sprintf(report_ctx->vif[0].ssid, "%s", "AirPro-2G-1");
    report_ctx->vif[0].num_sta = 0;                    
    report_ctx->vif[0].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[0].downlink_mb = rand() % 2000 + 1000;
   
    // 2nd vif
    sprintf(report_ctx->vif[1].radio, "%s", "BAND5G");
    sprintf(report_ctx->vif[1].ssid, "%s", "AirPro-5G-1");
    report_ctx->vif[1].num_sta = 20;                    
    report_ctx->vif[1].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[1].downlink_mb = rand() % 2000 + 1000;

    // 3 vif
    sprintf(report_ctx->vif[2].radio, "%s", "BAND2G");
    sprintf(report_ctx->vif[2].ssid, "%s", "AirPro-2G-2");
    report_ctx->vif[2].num_sta = 0;                    
    report_ctx->vif[2].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[2].downlink_mb = rand() % 2000 + 1000;

    // 4 vif
    sprintf(report_ctx->vif[3].radio, "%s", "BAND5G");
    sprintf(report_ctx->vif[3].ssid, "%s", "AirPro-5G-2");
    report_ctx->vif[3].num_sta = 0;                    
    report_ctx->vif[3].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[3].downlink_mb = rand() % 2000 + 1000;

    // 5 vif
    sprintf(report_ctx->vif[4].radio, "%s", "BAND2G");
    sprintf(report_ctx->vif[4].ssid, "%s", "AirPro-2G-3");
    report_ctx->vif[4].num_sta = 0;                    
    report_ctx->vif[4].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[4].downlink_mb = rand() % 2000 + 1000;

    // 6 vif
    sprintf(report_ctx->vif[5].radio, "%s", "BAND5G");
    sprintf(report_ctx->vif[5].ssid, "%s", "AirPro-5G-3");
    report_ctx->vif[5].num_sta = 0;                    
    report_ctx->vif[5].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[5].downlink_mb = rand() % 2000 + 1000;

    // 7 vif
    sprintf(report_ctx->vif[6].radio, "%s", "BAND2G");
    sprintf(report_ctx->vif[6].ssid, "%s", "AirPro-2G-4");
    report_ctx->vif[6].num_sta = 0;                    
    report_ctx->vif[6].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[6].downlink_mb = rand() % 2000 + 1000;

    // 8 vif
    sprintf(report_ctx->vif[7].radio, "%s", "BAND5G");
    sprintf(report_ctx->vif[7].ssid, "%s", "AirPro-5G-4");
    report_ctx->vif[7].num_sta = 0;                    
    report_ctx->vif[7].uplink_mb = rand() % 1000 + 500;       
    report_ctx->vif[7].downlink_mb = rand() % 2000 + 1000;


    report_ctx->n_radio = MAX_NUM_RADIO;

    sprintf(report_ctx->radio[0].band, "%s", "BAND2G");  
    report_ctx->radio[0].channel = 6;               
    report_ctx->radio[0].txpower = 25;              
    report_ctx->radio[0].channel_utilization = 20;      

    sprintf(report_ctx->radio[1].band, "%s", "BAND5G");  
    report_ctx->radio[1].channel = 36;               
    report_ctx->radio[1].txpower = 25;              
    report_ctx->radio[1].channel_utilization = 20;      
    return true;
}
