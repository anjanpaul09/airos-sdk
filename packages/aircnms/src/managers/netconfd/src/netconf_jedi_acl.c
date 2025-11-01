#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cm.h"

#define MAX_ENTRIES 16  // Maximum AccessControlList entries
#define MAC_LEN 18  // MAC format XX:XX:XX:XX:XX:XX
#define MAX_CMD_LEN 512
#define MAX_RESULT_LEN 256
#define FILE_PATH "/proc/airpro/stainfo"
#define IFNAME_LEN 10

typedef enum {
    ACL_DEFAULT = 0,
    ACL_WHITELIST = 1,
    ACL_BLACKLIST = 2
} acl_type;

// Function to convert MAC address to lowercase
void netconf_to_lowercase(char *str) 
{
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

// Get the interface name associated with a MAC address
bool get_ifname_by_mac(const char *mac, char *ifname, size_t ifname_size) 
{
    if (!mac || !ifname || ifname_size == 0) {
        fprintf(stderr, "Invalid arguments\n");
        return false;
    }

    FILE *fp = fopen(FILE_PATH, "r");
    if (!fp) {
        perror("Failed to open file");
        return false;
    }

    char line[256], file_mac[MAC_LEN], file_ifname[IFNAME_LEN], mac_lower[MAC_LEN];

    // Convert input MAC to lowercase for case-insensitive comparison
    strncpy(mac_lower, mac, MAC_LEN - 1);
    mac_lower[MAC_LEN - 1] = '\0';
    netconf_to_lowercase(mac_lower);

    while (fgets(line, sizeof(line), fp)) {
        char dummy1[32], dummy2[32];
        unsigned long dummy3, dummy4, dummy5;

        // Convert the entire line to lowercase for case-insensitive parsing
        netconf_to_lowercase(line);

        if (sscanf(line, "%17s %31s %31s %9s %lu %lu %lu",
                   file_mac, dummy1, dummy2, file_ifname, &dummy3, &dummy4, &dummy5) == 7) {
            netconf_to_lowercase(file_mac);

            if (strcmp(file_mac, mac_lower) == 0) {
                // Copy interface name safely
                strncpy(ifname, file_ifname, ifname_size - 1);
                ifname[ifname_size - 1] = '\0';
                fclose(fp);
                return true;
            }
        }
    }

    fclose(fp);
    return false;  // MAC address not found
}

// Function to execute system command and get output
void execute_command(const char *cmd, char *result, size_t size) 
{
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command: %s\n", cmd);
        return;
    }
    if (fgets(result, size, fp) != NULL) {
        result[strcspn(result, "\n")] = 0;  // Remove newline
    }
    pclose(fp);
}


// Function to add MAC address to AccessControlListX
void netconf_add_acl_entry(const char *profile, int index, const char *mac_address, acl_type type) 
{
    char cmd[MAX_CMD_LEN], result[MAX_RESULT_LEN], new_list[MAX_RESULT_LEN];

    // Get current ACL list
    snprintf(cmd, sizeof(cmd), "wificonf -f %s get AccessControlList%d", profile, index);
    execute_command(cmd, result, sizeof(result));

    // Check if MAC is already present
    if (strstr(result, mac_address)) {
        printf("MAC %s already exists in AccessControlList%d\n", mac_address, index);
        return;
    }

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "wificonf -f %s set AccessPolicy%d %d", profile, index, type);
    system(cmd);

    // Append new MAC address to the list
    if (strlen(result) > 0) {
        snprintf(new_list, sizeof(new_list), "%s;%s", result, mac_address);
    } else {
        snprintf(new_list, sizeof(new_list), "%s", mac_address);
    }

    // Update AccessControlListX
    snprintf(cmd, sizeof(cmd), "wificonf -f %s set AccessControlList%d \"%s\"", profile, index, new_list);
    system(cmd);

    system("wifi reload");
}

// Function to delete MAC address from AccessControlListX
void netconf_del_acl_entry(const char *profile, int index, const char *mac_address, acl_type type) 
{
    char cmd[MAX_CMD_LEN], result[MAX_RESULT_LEN], new_list[MAX_RESULT_LEN] = "";
    char *token, *temp_list;

    // Get current ACL list
    snprintf(cmd, sizeof(cmd), "wificonf -f %s get AccessControlList%d", profile, index);
    execute_command(cmd, result, sizeof(result));

    // If empty, nothing to delete
    if (strlen(result) == 0) {
        printf("AccessControlList%d is already empty\n", index);
        return;
    }

    // Tokenize and rebuild list without the MAC to delete
    temp_list = strdup(result);
    token = strtok(temp_list, ";");
    while (token) {
        if (strcmp(token, mac_address) != 0) {
            if (strlen(new_list) > 0) {
                strcat(new_list, ";");
            }
            strcat(new_list, token);
        }
        token = strtok(NULL, ";");
    }
    free(temp_list);
    
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "wificonf -f %s set AccessPolicy%d %d", profile, index, type);
    system(cmd);

    // Update AccessControlListX
    snprintf(cmd, sizeof(cmd), "wificonf -f %s set AccessControlList%d \"%s\"", profile, index, new_list);
    system(cmd);

}

// Function to clear all ACL entries
void netconf_clear_acl(const char *profile, acl_type type) {
    char cmd[256];

    for (int i = 0; i < MAX_ENTRIES; i++) {
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "wificonf -f %s set AccessPolicy%d %d", profile, i, type);
        system(cmd);
          
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "wificonf -f %s set AccessControlList%d ''", profile, i);
        system(cmd);
    }
    system("wifi reload");
}

int netconf_handle_add_blacklist(char *mac)
{
    char ifname[IFNAME_LEN];

    if (get_ifname_by_mac(mac, ifname, sizeof(ifname))) {
        int ifindex = map_interface_to_index(ifname);
        
        const char *wifi_profile_ra = RA_PROFILE;
        netconf_add_acl_entry(wifi_profile_ra, ifindex, mac, ACL_BLACKLIST); 
        
        const char *wifi_profile_rax = RAX_PROFILE;
        netconf_add_acl_entry(wifi_profile_rax, ifindex, mac, ACL_BLACKLIST); 
    }

    return 0;
}

int netconf_handle_remove_blacklist(char *mac)
{
    for (int i = 0; i < 3; i++) {
        const char *wifi_profile = get_config_file("ra");
        netconf_del_acl_entry(wifi_profile, i, mac, ACL_DEFAULT); 
    }
    for (int i = 0; i < 3; i++) {
        const char *wifi_profile = get_config_file("rax");
        netconf_del_acl_entry(wifi_profile, i, mac, ACL_DEFAULT); 
    }

    system("wifi reload");
    return 0;
}

int netconf_handle_add_whitelist(char *mac)
{
    char ifname[IFNAME_LEN];

    if (get_ifname_by_mac(mac, ifname, sizeof(ifname))) {
        int ifindex = map_interface_to_index(ifname);
        
        const char *wifi_profile_ra = RA_PROFILE;
        netconf_add_acl_entry(wifi_profile_ra, ifindex, mac, ACL_WHITELIST); 
        
        const char *wifi_profile_rax = RAX_PROFILE;
        netconf_add_acl_entry(wifi_profile_rax, ifindex, mac, ACL_WHITELIST); 
        
    }

    return 0;
}

int netconf_handle_remove_whitelist(char *mac)
{
    for (int i = 0; i < 3; i++) {
        const char *wifi_profile = get_config_file("ra");
        netconf_del_acl_entry(wifi_profile, i, mac, ACL_DEFAULT); 
    }
    for (int i = 0; i < 3; i++) {
        const char *wifi_profile = get_config_file("rax");
        netconf_del_acl_entry(wifi_profile, i, mac, ACL_DEFAULT); 
    }

    system("wifi reload");
    return 0;
}
