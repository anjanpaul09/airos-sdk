#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <radio_vif.h>
#include "cm.h"

#define MAX_INTERFACES 4
#define SSID_MAX_LEN 64
#define MODE_BUFFER 128
#define CMD_BUFFER 512

#define TYPE_AUTH_MODE "AuthMode"
#define TYPE_ENCRYPT_MODE "EncrypType"
#define TYPE_HIDESSID "HideSSID"

typedef enum {
    MODE_11BGN = 9,
    MODE_11AX = 16,
    MODE_11BGN_11AX = 16,
    MODE_11NA = 8,
    MODE_11AC = 15,
    MODE_11NA_11AC_11AX = 17
} WirelessMode;

typedef enum {
    BW_20MHZ = 0,
    BW_40MHZ = 1
} BandwidthHT;

typedef enum {
    VHT_DISABLED = 0,
    VHT_ENABLED = 1
} BandwidthVHT;

// Structure to hold interface mappings
typedef struct {
    char wlan[12];
    char ra[12];
} InterfaceMapping;

// Define the mappings
InterfaceMapping mappings[8] = {
    {"wlan1", "ra0"},  {"wlan2", "rax0"},
    {"wlan3", "ra1"},  {"wlan4", "rax1"},
    {"wlan5", "ra2"},  {"wlan6", "rax2"},
    {"wlan7", "ra3"},  {"wlan8", "rax3"}
};

// Function to get raX/raxX from wlanX
const char* get_mapped_interface(const char* wlan) 
{
    for (int i = 0; i < 8; i++) {
        if (strcmp(mappings[i].wlan, wlan) == 0) {
            return mappings[i].ra;
        }
    }
    return NULL;  // Not found
}

const char *get_config_file(const char *iface) 
{
    if (strncmp(iface, "rax", 3) == 0) {
        return RAX_PROFILE;  // b1.dat for rax
    } else if (strncmp(iface, "ra", 2) == 0) {
        return RA_PROFILE;  // b0.dat for ra
    }
    return NULL;  // Invalid interface
}

int map_interface_to_index(const char *iface) 
{
    if (strncmp(iface, "ra", 2) == 0 || strncmp(iface, "rax", 3) == 0) {
        int index;
        if (sscanf(iface + (iface[2] == 'x' ? 3 : 2), "%d", &index) == 1) {
            if (index >= 0 && index <= 3) {
                return index;  // Mapping: 0->1, 1->2, 2->3, 3->4
            }
        }
    }
    return -1; // Return -1 for unknown interfaces
}

void get_jedi_encryption_type(char *encrypt_type, char *encryption)
{
    if(!strncmp(encryption, "none",4)) {
        strcpy(encrypt_type, "OPEN");
    } else if (!strncmp(encryption, "psk2",3)) {
        strcpy(encrypt_type, "WPA2PSK");
    } else {
        strcpy(encrypt_type,"OPEN");
    }

    return;
}

// Function to get AuthMode from wificonf
int jedi_get_current_param(const char *config_file, char *buffer, size_t size, char *param) 
{
    FILE *fp;
    char cmd[CMD_BUFFER];

    snprintf(cmd, sizeof(cmd), "wificonf -f %s get %s", config_file, param);
    
    // Execute command and read output
    if ((fp = popen(cmd, "r")) == NULL) {
        perror("popen failed");
        return -1;
    }

    if (fgets(buffer, size, fp) == NULL) {
        perror("fgets failed");
        pclose(fp);
        return -1;
    }

    pclose(fp);
    return 0;
}

int jedi_set_dat_param(const char *config_file, int iface_index, char *new_mode, char *param) 
{
    char current_param[MODE_BUFFER] = {0};
    char *tokens[MAX_INTERFACES] = {NULL};
    char command[CMD_BUFFER];

    // Get the current param
    if (jedi_get_current_param(config_file, current_param, sizeof(current_param), param) != 0) {
        fprintf(stderr, "Failed to get param\n");
        return -1;
    }

    // Ensure null termination
    current_param[strcspn(current_param, "\r\n")] = '\0';

    // Tokenize current_param
    char temp[MODE_BUFFER];
    strncpy(temp, current_param, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char *token = strtok(temp, ";");
    int index = 0;

    while (token != NULL && index < MAX_INTERFACES) {
        tokens[index] = strdup(token);
        if (!tokens[index]) {
            fprintf(stderr, "Memory allocation failed for tokens[%d]\n", index);
            goto cleanup;
        }
        index++;
        token = strtok(NULL, ";");
    }

    // Fill missing interfaces
    for (int i = index; i < MAX_INTERFACES; i++) {
        if (strcmp(param, TYPE_AUTH_MODE) == 0)
            tokens[i] = strdup("OPEN");
        else if (strcmp(param, TYPE_ENCRYPT_MODE) == 0)
            tokens[i] = strdup("NONE");
        else if (strcmp(param, TYPE_HIDESSID) == 0)
            tokens[i] = strdup("0");

        if (!tokens[i]) {
            fprintf(stderr, "Memory allocation failed for tokens[%d]\n", i);
            goto cleanup;
        }
    }


    // Check if update is needed
    if (strcmp(tokens[iface_index], new_mode) == 0) {
        //printf("%s for interface %d is already set to '%s', no update needed.\n", param, iface_index, new_mode);
        goto cleanup;
    }

    // Modify the specified interface
    free(tokens[iface_index]);
    tokens[iface_index] = strdup(new_mode);
    if (!tokens[iface_index]) {
        fprintf(stderr, "Memory allocation failed for tokens[%d]\n", iface_index);
        goto cleanup;
    }


    // Set wireless flag
    set_flag(&flags, FLAG_WIRELESS_CHANGE);

    // Construct the new param string
    snprintf(command, sizeof(command), "wificonf -f %s set %s '", config_file, param);
    for (int i = 0; i < MAX_INTERFACES; i++) {
        strncat(command, tokens[i], sizeof(command) - strlen(command) - 1);
        if (i < MAX_INTERFACES - 1) {
            strncat(command, ";", sizeof(command) - strlen(command) - 1);
        }
    }
    strncat(command, "'", sizeof(command) - strlen(command) - 1);


    // Execute the command
    if (system(command) != 0) {
        fprintf(stderr, "Failed to update %s\n", param);
        goto cleanup;
    }


cleanup:
    // Free allocated memory
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (tokens[i]) {
            free(tokens[i]);
            tokens[i] = NULL;
        }
    }
    return 0;
}



int jedi_set_nat_interface(const char *mapped_interface)
{
    FILE *fp;
    char cmd[CMD_BUFFER];
    char output[256];
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "uci get network.nat_network.ifname");
    
    if ((fp = popen(cmd, "r")) == NULL) {
        perror("popen failed");
        return -1;
    }
    
    if (fgets(output, sizeof(output), fp) != NULL) {
        output[strcspn(output, "\n")] = '\0';

        if (strstr(output, "uci: Entry not found") != NULL) {
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "uci add_list network.nat_network.ifname=%s", mapped_interface);
            system(cmd);
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "uci commit network");
            system(cmd);
            //Set network flag 
            //set_flag(&flags, FLAG_NETWORK_CHANGE);
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "ifup nat_network");
            system(cmd);
        } else if (strstr(output, mapped_interface) != NULL) {
            //printf("Interface '%s' is present.\n", mapped_interface);
        } else {
            //printf("Interface '%s' is NOT present.\n", mapped_interface);
            
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "uci add_list network.nat_network.ifname=%s", mapped_interface);
            system(cmd);
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "uci commit network");
            system(cmd);
            //set network flag
            //set_flag(&flags, FLAG_NETWORK_CHANGE);
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "ifup nat_network");
            system(cmd);
        }
    } else {
        //printf("Failed to get interface information.\n");
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "uci add_list network.nat_network.ifname=%s", mapped_interface);
        system(cmd);
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "uci commit network");
        system(cmd);    
        //set network flag
        //set_flag(&flags, FLAG_NETWORK_CHANGE);
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "ifup nat_network");
        system(cmd);
    }
    
    pclose(fp);

    return 0;
}

// Function to check if the mapped interface exists in NAT
int jedi_check_ifname_in_nat(const char *mapped_interface) 
{
    char cmd[CMD_BUFFER];
    char result[CMD_BUFFER] = {0};

    // Command to get the current list of NAT interfaces
    snprintf(cmd, sizeof(cmd), "uci get network.nat_network.ifname 2>/dev/null");

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("Failed to execute uci get command");
        return -1;
    }

    // Read the result from the command
    if (fgets(result, sizeof(result), fp) == NULL) {
        pclose(fp);
        return 0;  // Interface not found
    }

    pclose(fp);

    // Check if the interface is present in the output
    if (strstr(result, mapped_interface) != NULL) {
        return 1;  // Interface exists
    }
    return 0;  // Interface does not exist
}

// Function to remove an interface from NAT if it exists
int jedi_remove_from_nat(const char *mapped_interface) 
{
    char cmd[CMD_BUFFER];

    // Check if the interface is present in NAT
    if (jedi_check_ifname_in_nat(mapped_interface)) {
        snprintf(cmd, sizeof(cmd), "uci del_list network.nat_network.ifname=%s", mapped_interface);
        system(cmd);

        snprintf(cmd, sizeof(cmd), "uci commit network");
        system(cmd);

        //set network flag
        //set_flag(&flags, FLAG_NETWORK_CHANGE);
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "ifup nat_network");
        system(cmd);
        LOG(INFO, "Removed %s from NAT\n", mapped_interface);
    } else {
        LOG(INFO, "Interface %s not found in NAT. No action taken.\n", mapped_interface);
    }

    return 0;
}

// Function to update SSID if different from current value
void jedi_update_ssid(const char *config_file, const char *interface, int iface_index, const char *new_ssid) 
{
    char command[CMD_BUFFER];
    char current_ssid[SSID_MAX_LEN] = {0};

    snprintf(command, sizeof(command), "wificonf -f %s get SSID%d", config_file, iface_index + 1);
    execute_command(command, current_ssid, sizeof(current_ssid));

    if (strcmp(current_ssid, new_ssid) != 0) {
        //printf("Updating SSID from '%s' to '%s'\n", current_ssid, new_ssid);
        LOG(INFO, "Updating SSID from '%s' to '%s'\n", current_ssid, new_ssid);

        snprintf(command, sizeof(command), "wificonf -f %s set SSID%d \"%s\"", config_file, iface_index + 1, new_ssid);
        system(command);

        snprintf(command, sizeof(command), "iwpriv %s set ssid=\"%s\"", interface, new_ssid);
        system(command);

        //set wireless flag
        set_flag(&flags, FLAG_WIRELESS_CHANGE);
    } else {
        //printf("SSID is already set to '%s', no changes needed.\n", current_ssid);
        LOG(INFO, "SSID is already set to '%s', no changes needed.\n", current_ssid);
    }
}

int jedi_set_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params)
{
    int ret;
    int iface_index;
    char command[CMD_BUFFER];
    char auth_type[12];
    const char *mapped_interface = get_mapped_interface(vap_name);
    const char *config_file = get_config_file(mapped_interface);

    iface_index = map_interface_to_index(mapped_interface);
    
    memset(command, 0, sizeof(command));
    sprintf(command, "ip link %s up", mapped_interface); 
    system(command);
    
    //SSID
    jedi_update_ssid(config_file, mapped_interface, iface_index, vap_params->ssid);

    //TODO: ADD OTHER ENCRYPTION MODE
    get_jedi_encryption_type(auth_type, vap_params->encryption); 
    ret = jedi_set_dat_param(config_file, iface_index, auth_type, TYPE_AUTH_MODE);
    memset(command, 0, sizeof(command));
    sprintf(command, "iwpriv %s set AuthMode=%s", mapped_interface, auth_type); 
    system(command);
    if (!strcmp(auth_type, "WPA2PSK")) {
        
        //Encrypt 
        ret = jedi_set_dat_param(config_file, iface_index, "AES", TYPE_ENCRYPT_MODE);
        memset(command, 0, sizeof(command));
        sprintf(command, "iwpriv %s set EncrypType=%s", mapped_interface, "AES"); 
        system(command);
       
        //key
        memset(command, 0, sizeof(command));
        sprintf(command, " wificonf -f %s set WPAPSK%d '%s'", config_file, iface_index + 1, vap_params->key); 
        system(command);
        memset(command, 0, sizeof(command));
        sprintf(command, "iwpriv %s set WPAPSK=%s", mapped_interface, vap_params->key); 
        system(command);
    
    } else if (!strcmp(auth_type, "OPEN")) {
        ret = jedi_set_dat_param(config_file, iface_index, "NONE", TYPE_ENCRYPT_MODE);
        memset(command, 0, sizeof(command));
        sprintf(command, "iwpriv %s set EncrypType=%s", mapped_interface, "NONE"); 
        system(command);
    } 

    //HIDDEN
    ret = jedi_set_dat_param(config_file, iface_index, vap_params->hide_ssid, TYPE_HIDESSID);
    memset(command, 0, sizeof(command));
    sprintf(command, "iwpriv %s set HideSSID=%s", mapped_interface, vap_params->hide_ssid); 
    system(command);

    //NAT
    if( strcmp(vap_params->forward_type, "NAT") == 0) {
        check_existing_vlan(mapped_interface);
        jedi_set_nat_interface(mapped_interface);
    } else {
        jedi_remove_from_nat(mapped_interface);
    }

    
    //VLAN
    if( strcmp(vap_params->forward_type, "Bridge") == 0) {
        int vlan = atoi(vap_params->vlan_id);
        if (vlan == 0) {
            check_existing_vlan(mapped_interface);
        } else if (vlan > 0) {
            check_existing_vlan(mapped_interface);
            set_vlan_network(vlan, mapped_interface);
        }
    }
    
    // INTERFACE UPRATE
    if( vap_params->is_uprate) {
        air_interface_rate_limit(mapped_interface, vap_params->uprate, AIR_DIR_UPLINK);
    }
    //INTERFACE DOWNRATE
    if( vap_params->is_downrate) {
        air_interface_rate_limit(mapped_interface, vap_params->downrate, AIR_DIR_DOWNLINK);
    }
            
    return ret;
}

int jedi_del_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params)
{
    char command[CMD_BUFFER];
    const char *mapped_interface = get_mapped_interface(vap_name);
    
    memset(command, 0, sizeof(command));
    sprintf(command, "ip link set %s down", mapped_interface); 
    system(command);

    return 0;
}

const char* map_wifi(const char* uci_radio_name) 
{
    if (strcmp(uci_radio_name, "wifi0") == 0) return "rax0"; //change naming 
    if (strcmp(uci_radio_name, "wifi1") == 0) return "ra0";
    return "unknown"; // Default case
}

void trim_newline(char *str) 
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

int jedi_set_hwmode(const char *radio_name, const char *config_file, char *hwmode)
{
    WirelessMode w_mode = 0;
    char command[CMD_BUFFER];
    char buffer[CMD_BUFFER];
    char full_w_mode[64];

    if ( strcmp(radio_name, "ra0") == 0) {//2.4ghz
        if (strcmp(hwmode, "11BGN") == 0) {
            w_mode = MODE_11BGN; 
        } else if(strcmp(hwmode, "11AX") == 0) {
            w_mode = MODE_11AX;
        } else if(strcmp(hwmode, "11BGN_11AX") == 0) {
            w_mode = MODE_11BGN_11AX;
        }
 
    } else if (strcmp(radio_name, "rax0") == 0) {//5ghz
        if(strcmp(hwmode, "11NA") == 0){
            w_mode = MODE_11NA;
        } else if(strcmp(hwmode, "11AC") == 0){
            w_mode = MODE_11AC;
        } else if(strcmp(hwmode, "11AX") == 0) {
            w_mode = MODE_11NA_11AC_11AX;
        } else if(strcmp(hwmode, "11NA_11AC_11AX") == 0){
            w_mode = MODE_11NA_11AC_11AX;
        }
    } 

    // Validate mode before executing command
    if (w_mode == -1) {
        fprintf(stderr, "Error: Invalid hardware mode provided.\n");
        return -1;
    }

    // Fetch current WirelessMode
    if (jedi_get_current_param(config_file, buffer, sizeof(buffer), "WirelessMode") == 0) {
        trim_newline(buffer);  // Remove trailing newline if present
        snprintf(full_w_mode, sizeof(full_w_mode), "%d;%d;%d;%d", w_mode, w_mode, w_mode, w_mode);
        
        if ( strcmp(buffer, full_w_mode) == 0) {
            //printf("WirelessMode is already set to %d, no change needed.\n", w_mode);
            LOG(INFO, "WirelessMode is already set to %d, no change needed.\n", w_mode);
            return 0;
        }
    }

    // Set new WirelessMode
    snprintf(command, sizeof(command)," wificonf -f %s set WirelessMode %d;%d;%d;%d", config_file, w_mode, w_mode, w_mode, w_mode); 
    
    //set wireless flag
    set_flag(&flags, FLAG_WIRELESS_CHANGE);

    int ret = system(command);
    if (ret != 0) {
        fprintf(stderr, "Error: Command execution failed.\n");
        return -1;
    }

    printf("WirelessMode updated successfully.\n");

    return 0;
}


int jedi_set_bandwidth(const char *radio_name, const char *config_file, char *chan_bw)
{
    char command[CMD_BUFFER];
    char buffer[CMD_BUFFER];
    BandwidthHT HT_BW = BW_20MHZ;
    BandwidthVHT VHT_BW = VHT_DISABLED;

    if (strcmp(radio_name, "ra0") == 0) { // 2.4GHz
        if (strcmp(chan_bw, "20") == 0) {
            HT_BW = BW_20MHZ;
            VHT_BW = VHT_DISABLED;
        } else if (strcmp(chan_bw, "40") == 0) {
            HT_BW = BW_40MHZ;
            VHT_BW = VHT_DISABLED;
        }
    } else if (strcmp(radio_name, "rax0") == 0) { // 5GHz
        if (strcmp(chan_bw, "20") == 0) {
            HT_BW = BW_20MHZ;
            VHT_BW = VHT_DISABLED;
        } else if (strcmp(chan_bw, "40") == 0) {
            HT_BW = BW_40MHZ;
            VHT_BW = VHT_DISABLED;
        } else if (strcmp(chan_bw, "80") == 0) {
            HT_BW = BW_40MHZ;  
            VHT_BW = VHT_ENABLED;
        }
    }


    // Read current HT_BW
    if (jedi_get_current_param(config_file, buffer, sizeof(buffer), "HT_BW") == 0) {
        int current_HT_BW = atoi(buffer);
        if (current_HT_BW != HT_BW) {
            snprintf(command, sizeof(command), "wificonf -f %s set HT_BW %d", config_file, HT_BW);
            
            //set wireless flag
            set_flag(&flags, FLAG_WIRELESS_CHANGE);
            
            if (system(command) != 0) {
                fprintf(stderr, "Error: Failed to update HT_BW.\n");
                return -1;
            }
        }
    }

    // Read current VHT_BW
    if (jedi_get_current_param(config_file, buffer, sizeof(buffer), "VHT_BW") == 0) {
        int current_VHT_BW = atoi(buffer);
        if (current_VHT_BW != VHT_BW) {
            snprintf(command, sizeof(command), "wificonf -f %s set VHT_BW %d", config_file, VHT_BW);
        
            //set wireless flag
            set_flag(&flags, FLAG_WIRELESS_CHANGE);
            
            if (system(command) != 0) {
                fprintf(stderr, "Error: Failed to update VHT_BW.\n");
                return -1;
            }
        }
    }

    return 0;
}

int jedi_set_primary_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params)
{
    const char *phy_name = map_wifi(radio_name);
    const char *config_file = get_config_file(phy_name);
   
    //radio enable/disable
    // channel width
    jedi_set_bandwidth(phy_name, config_file, radio_params->channel_width);
    jedi_set_hwmode(phy_name, config_file, radio_params->hwmode);
    
    return 0;
}

// Function to update a parameter only if it's different
int jedi_update_param(const char *config_file, const char *phy_name, const char *param, const char *new_value) 
{
    char current_value[CMD_BUFFER] = {0};

    if (jedi_get_current_param(config_file, current_value, sizeof(current_value), (char *)param) == 0) {
        if (strcmp(current_value, new_value) == 0) {
            //printf("%s is already set to '%s', no update needed.\n", param, new_value);
            LOG(INFO, "%s is already set to '%s', no update needed.\n", param, new_value);
            return 0; // No need to update
        }
    }

    char command[CMD_BUFFER];

    // Update iwpriv setting
    snprintf(command, sizeof(command), "iwpriv %s set %s='%s'", phy_name, param, new_value);
    system(command);

    // Update wificonf setting
    snprintf(command, sizeof(command), "wificonf -f %s set %s %s", config_file, param, new_value);
    system(command);

    //set wireless flag
    set_flag(&flags, FLAG_WIRELESS_CHANGE);
    //printf("Updated %s to '%s'\n", param, new_value);
    LOG(INFO, "Updated %s to '%s'\n", param, new_value);
    return 0;
}

// Main function to update radio parameters
int jedi_set_secondary_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params) 
{
    const char *phy_name = map_wifi(radio_name);
    const char *config_file = get_config_file(phy_name);
 
    // Update channel only if different
    jedi_update_param(config_file, phy_name, "Channel", radio_params->channel);

    // Update txpower only if different
    jedi_update_param(config_file, phy_name, "TxPower", radio_params->txpower);

    return 0;
}

