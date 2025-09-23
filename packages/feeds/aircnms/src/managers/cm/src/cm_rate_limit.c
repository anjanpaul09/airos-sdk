#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>  // For if_nametoindex
#include "airdpi/air_ioctl.h"

#define MAX_OUTPUT_LEN 1024

const char* get_ifname_from_secname(const char *section) {
    static char ifname[MAX_OUTPUT_LEN];
    char command[MAX_OUTPUT_LEN];

    // Construct the ubus command with the section name argument
    snprintf(command, sizeof(command),
             "ubus call network.wireless status | grep -A 5 '\"section\": \"%s\"' | grep '\"ifname\"' | awk -F'\"' '{print $4}'",
             section);

    // Open a process to run the command
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return NULL;
    }

    // Read the output from the command
    if (fgets(ifname, sizeof(ifname), fp) != NULL) {
        // Remove trailing newline if present
        size_t len = strlen(ifname);
        if (len > 0 && ifname[len - 1] == '\n') {
            ifname[len - 1] = '\0';
        }
    }

    // Close the file pointer
    fclose(fp);

    // Return the interface name
    return ifname[0] != '\0' ? ifname : NULL;
}

unsigned int get_ifindex_from_ifname(const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        // If ifindex is 0, an error occurred (interface not found)
        perror("if_nametoindex failed");
        return 0; // Return 0 if the interface was not found
    }

    return ifindex;
}

int get_ifindex_from_sysfs(const char *ifname) {
    char path[256];
    FILE *file;
    int ifindex = -1;

    // Construct the sysfs path
    snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", ifname);

    // Open the file
    file = fopen(path, "r");
    if (!file) {
        perror("Failed to open ifindex file");
        return -1;
    }

    // Read the ifindex value
    if (fscanf(file, "%d", &ifindex) != 1) {
        perror("Failed to read ifindex value");
        ifindex = -1;
    }

    // Close the file
    fclose(file);

    return ifindex;
}

void air_interface_rate_limit(char *vif_name, int rate, int dir, char *type)
{
    struct adpi_ratelimit_bucket crb;
#ifdef CONFIG_PLATFORM_MTK_JEDI
    int ifindex = IFNAME_HASH(vif_name);
#else
    const char *ifname = get_ifname_from_secname(vif_name);
    int ifindex = IFNAME_HASH(ifname);
#endif
    int fd;

    // Populate the adpi_ratelimit_bucket structure
    memset(&crb, 0, sizeof(crb));
    crb.wlan_idx = ifindex;
    crb.bytes_per_sec = rate * 125000;  //mb to bytes
    if (rate) {
        crb.size = crb.bytes_per_sec;
    }
    crb.direction = dir;

    // Open the device file for the ioctl
    fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device file");
        return;
    }

    if (strcmp(type, "wlan") == 0) {
        // Call the ioctl
        if (ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN, &crb) < 0) {
            perror("ioctl failed");
        } else {
            printf("Rate limit set successfully: ifindex=%d, rate=%d, dir=%d\n", crb.wlan_idx, rate, dir);
        }
    } else if (strcmp(type, "wlan_per_user") == 0) {
        // Call the ioctl
        if (ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN_PER_USER, &crb) < 0) {
            perror("ioctl failed");
        } else {

            printf("Wlan Per User Rate limit set successfully: ifindex=%d, rate=%d, dir=%d\n", crb.wlan_idx, rate, dir);
        }
    }

    // Close the device file
    close(fd);
}

void air_user_rate_limit(uint8_t *mac, int rate, int dir)
{
    struct adpi_ratelimit_bucket crb;
    int fd;

    // Populate the adpi_ratelimit_bucket structure
    memset(&crb, 0, sizeof(crb));
    memcpy(crb.macaddr, mac, MAX_MAC_ADDR_LEN);
    crb.bytes_per_sec = rate * 125000;  //mb to bytes
    if (rate) {
        crb.size = crb.bytes_per_sec;
    }
    crb.direction = dir;

    // Open the device file for the ioctl
    fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device file");
        return;
    }

    // Call the ioctl
    if (ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN_USER, &crb) < 0) {
        perror("ioctl failed");
    } else {
        printf("Rate limit user set successfully: rate=%d, dir=%d\n", rate, dir);
    }

    // Close the device file
    close(fd);
}


