#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_INTERFACES 8
#define MAX_OUTPUT 256
#define CMD_BUFFER 256

// Structure to hold interface mappings
typedef struct {
    char wlan[12];
    char ra[12];
} interface_mapping_t;


// Define the mappings
interface_mapping_t mapping[8] = {
    {"wlan1", "ra0"},  {"wlan2", "rax0"},
    {"wlan3", "ra1"},  {"wlan4", "rax1"},
    {"wlan5", "ra2"},  {"wlan6", "rax2"},
    {"wlan7", "ra3"},  {"wlan8", "rax3"}
};

// Helper function: check if a given wireless interface is disabled
bool is_interface_disabled(const char *iface) {
    char cmd[256];
    char output[MAX_OUTPUT];
    FILE *fp;
    bool disabled = false;

    snprintf(cmd, sizeof(cmd), "uci get wireless.%s.disabled 2>/dev/null", iface);
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen failed");
        return false;
    }
    
    if (fgets(output, sizeof(output), fp) != NULL) {
        output[strcspn(output, "\n")] = '\0';
        if (strcmp(output, "1") == 0) {
            disabled = true;
        }
    }
    pclose(fp);
    return disabled;
}

void cm_check_radio_config(void)
{
    char command[CMD_BUFFER];

    if (is_interface_disabled("wifi0")) {
        system("ip link set rax0 down");
        system("ip link set rax1 down");
        system("ip link set rax2 down");
        system("ip link set rax3 down");
    }

    if (is_interface_disabled("wifi1")) {
        system("ip link set ra0 down");
        system("ip link set ra1 down");
        system("ip link set ra2 down");
        system("ip link set ra3 down");
    }

}

bool cm_check_wifi_config(void) 
{
    char command[CMD_BUFFER];

    sleep(20); // Sleep for 20 seconds
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (is_interface_disabled(mapping[i].wlan)) {
            printf("Interface %s is disabled.\n", mapping[i].ra);
            
            memset(command, 0, sizeof(command));
            sprintf(command, "ip link set %s down", mapping[i].ra); 
            system(command);
        } else {
            memset(command, 0, sizeof(command));
            sprintf(command, "ip link set %s up", mapping[i].ra); 
            system(command);
            printf("Interface %s is enabled.\n", mapping[i].ra);
        }
    }

    cm_check_radio_config();
    return true;
}

