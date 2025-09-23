#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/vfs.h>

#include "util.h"
#include "log.h"
#include "dpp_client.h"


#define AIRDPI_CLIENT_INFO_FILE  "/proc/sys/air/node_tble/info"

bool target_dhcp_client_get(uint8_t *macaddr, dpp_client_dhcp_t *cl)
{
    int32_t     rc;
    const char  *filename = AIRDPI_CLIENT_INFO_FILE;
    FILE        *proc_file = NULL;
    char        buf[256] = { 0 };

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        LOG(ERR, "Parsing client details (Failed to open %s)", filename);
        return false;
    }

    while (fgets(buf, sizeof(buf), proc_file) != NULL)
    {
    char ipaddr[32] = { 0 };
	char macstr[32] = { 0 };
	char hostname[32] = { 0 };
	char mac[6] = { 0 };

        if (sscanf(buf, "%s %s %s", macstr, ipaddr, hostname) != 3) {
            goto parse_error;
        }

	if (sscanf(macstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
             printf("Failed to parse MAC address.\n");
            goto parse_error;
        }

	if (!memcmp(mac, macaddr, 6)) {
            strcpy(cl->ipaddr, ipaddr);
            strcpy(cl->hostname, hostname);
	    break;
	}
    }

    fclose(proc_file);
    return true;

parse_error:
    fclose(proc_file);
    LOG(ERROR, "Error parsing %s.", filename);
    return false;
}
