#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_INTERFACES 8
#define MAX_OUTPUT 256
#define CMD_BUFFER 256

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

// Helper function: check if a given wireless interface is disabled
bool is_interface_disabled(const char *iface) {
    char cmd[256];
    char output[MAX_OUTPUT];
    FILE *fp;
    bool disabled = false;

    // Build the command to get the 'disabled' option for this interface.
    // We assume the UCI section name is the interface name (adjust if needed).
    snprintf(cmd, sizeof(cmd), "uci get wireless.%s.disabled 2>/dev/null", iface);
    
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen failed");
        return false;
    }
    
    // Read the output
    if (fgets(output, sizeof(output), fp) != NULL) {
        // Remove trailing newline
        output[strcspn(output, "\n")] = '\0';
        // If the output equals "1", the interface is disabled.
        if (strcmp(output, "1") == 0) {
            disabled = true;
        }
    }
    pclose(fp);
    return disabled;
}

void sm_check_radio_config(void) 
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

bool sm_check_wifi_config(void) 
{
    char command[CMD_BUFFER];

    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (is_interface_disabled(mappings[i].wlan)) {
            printf("Interface %s is disabled.\n", mappings[i].ra);
            
            memset(command, 0, sizeof(command));
            sprintf(command, "ip link set %s down", mappings[i].ra); 
            system(command);
        } else {
            printf("Interface %s is enabled.\n", mappings[i].ra);
        }
    }
    sm_check_radio_config();
    return true;
}

