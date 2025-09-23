#ifndef AIR_CLI_H
#define AIR_CLI_H

#include <stdint.h>  // Ensure uint32_t is defined

void cmd_get_user_rate_limit(const char *mac_str);
void cmd_get_wlan_rate_limit(const char *ifname);
void cmd_set_user_rate_limit(const char *mac_addr, uint32_t rate, const char *direction);
void cmd_set_wlan_rate_limit(const char *interface, uint32_t rate, const char *direction);

#endif // AIR_CLI_H

