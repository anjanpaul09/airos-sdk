#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>  
#include <fcntl.h>      // For open and O_RDWR
#include <unistd.h>     // For close
#include <sys/ioctl.h>  // For ioctl
#include <arpa/inet.h>
#include "airdpi/air_ioctl.h"

#include "air_cli.h"

enum {
    AIR_DIR_UPLINK,
    AIR_DIR_DOWNLINK,
    AIR_DIR_MAX
};

// Command function declarations
int cmd_get_all_top_domains();
int cmd_get_all_clients();
void cmd_help();
void cmd_exit();
void cmd_block_domain(const char *domain);
void cmd_unblock_domain(const char *domain);

void process_command(const char *command, int argc, char *argv[]) 
{
    if (strcmp(command, "get_all_clients") == 0) {
        cmd_get_all_clients();
    } else if (strcmp(command, "get_all_top_domains") == 0) {
        cmd_get_all_top_domains();
    } else if (strcmp(command, "get_user_rate_limit") == 0) {
        const char *mac_arg = NULL;

        // Parse arguments for the -m flag
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
                mac_arg = argv[i + 1];
                break;
            }
        }

        if (!mac_arg) {
            printf("Error: Missing MAC address. Use -m <MAC_ADDRESS>.\n");
            return;
        }

        cmd_get_user_rate_limit(mac_arg);
    } else if (strcmp(command, "get_wlan_rate_limit") == 0) {
        if (argc < 3 || strcmp(argv[2], "-i") != 0) {
            printf("Usage: air_cli get_wlan_rate_limit -i 'interface_name'\n");
            return;
        }
        cmd_get_wlan_rate_limit(argv[3]);
    } else if (strcmp(command, "set_user_rate_limit") == 0) {
        const char *mac_arg = NULL;
        uint32_t rate = 0;
        const char *direction = NULL;

        // Parse arguments for -m (MAC address), -r (rate), and -d (direction)
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
                mac_arg = argv[i + 1];
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                rate = atoi(argv[i + 1]);
            } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                direction = argv[i + 1];
            }
        }

        if (!mac_arg) {
            printf("Error: Missing MAC address. Use -m <MAC_ADDRESS>.\n");
            return;
        }

        if (rate < 0) {
            printf("Error: Invalid rate value. Use -r <rate>.\n");
            return;
        }

        if (!direction || (strcmp(direction, "up") != 0 && strcmp(direction, "down") != 0)) {
            printf("Error: Invalid direction. Use -d <up/down>.\n");
            return;
        }

        cmd_set_user_rate_limit(mac_arg, rate, direction);
    } else if (strcmp(command, "set_wlan_rate_limit") == 0) {
        const char *interface = NULL;
        uint32_t rate = 0;
        const char *direction = NULL;

        // Parse arguments for -i (interface), -r (rate), and -d (direction)
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
                interface = argv[i + 1];
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                rate = atoi(argv[i + 1]);
            } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                direction = argv[i + 1];
            }
        }

        if (!interface) {
            printf("Error: Missing interface name. Use -i <interface_name>.\n");
            return;
        }

        if (rate < 0) {
            printf("Error: Invalid rate value. Use -r <rate>.\n");
            return;
        }

        if (!direction || (strcmp(direction, "up") != 0 && strcmp(direction, "down") != 0)) {
            printf("Error: Invalid direction. Use -d <up/down>.\n");
            return;
        }

        cmd_set_wlan_rate_limit(interface, rate, direction); 
    } else if (strcmp(command, "block_domain") == 0) {
        const char *domain = NULL;

        // Parse arguments for the -d flag
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                domain = argv[i + 1];
                break;
            }
        }

        if (!domain || strlen(domain) == 0) {
            printf("Error: Missing or empty domain name. Use -d <domain_name>.\n");
            return;
        }

        cmd_block_domain(domain);
    } else if (strcmp(command, "unblock_domain") == 0) {
        const char *domain = NULL;

        // Parse arguments for the -d flag
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                domain = argv[i + 1];
                break;
            }
        }

        if (!domain || strlen(domain) == 0) {
            printf("Error: Missing or empty domain name. Use -d <domain_name>.\n");
            return;
        }

        cmd_unblock_domain(domain);
    } else if (strcmp(command, "help") == 0) {
        cmd_help();
    } else if (strcmp(command, "exit") == 0) {
        cmd_exit();
    } else {
        printf("Unknown command: %s\n", command);
        printf("Type 'help' for a list of available commands.\n");
    }
}

void cmd_block_domain(const char *domain)
{
    // Validate domain length
    if (strlen(domain) >= MAX_DOMAIN_NAME_LEN) {
        printf("Error: Domain name too long (max %d characters).\n", MAX_DOMAIN_NAME_LEN - 1);
        return;
    }

    // Open the device (/dev/air)
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }

    // Prepare domain buffer
    char domain_buf[MAX_DOMAIN_NAME_LEN];
    strncpy(domain_buf, domain, MAX_DOMAIN_NAME_LEN - 1);
    domain_buf[MAX_DOMAIN_NAME_LEN - 1] = '\0';

    // Send IOCTL to kernel
    if (ioctl(fd, IOCTL_ADPI_BLOCK_DOMAIN, domain_buf) < 0) {
        perror("ioctl");
        close(fd);
        return;
    }

    printf("Domain blocked: %s\n", domain);
    close(fd);
}

void cmd_unblock_domain(const char *domain)
{
    // Validate domain length
    if (strlen(domain) >= MAX_DOMAIN_NAME_LEN) {
        printf("Error: Domain name too long (max %d characters).\n", MAX_DOMAIN_NAME_LEN - 1);
        return;
    }

    // Open the device (/dev/air)
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }

    // Prepare domain buffer
    char domain_buf[MAX_DOMAIN_NAME_LEN];
    strncpy(domain_buf, domain, MAX_DOMAIN_NAME_LEN - 1);
    domain_buf[MAX_DOMAIN_NAME_LEN - 1] = '\0';

    // Send IOCTL to kernel
    if (ioctl(fd, IOCTL_ADPI_UNBLOCK_DOMAIN, domain_buf) < 0) {
        perror("ioctl");
        close(fd);
        return;
    }

    printf("Domain unblocked: %s\n", domain);
    close(fd);
}

void cmd_set_user_rate_limit(const char *mac_addr, uint32_t rate, const char *direction) 
{
    struct adpi_ratelimit_bucket crb;
    memset(&crb, 0, sizeof(crb));

    // Convert MAC address string to binary format
    if (sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &crb.macaddr[0], &crb.macaddr[1], &crb.macaddr[2],
                           &crb.macaddr[3], &crb.macaddr[4], &crb.macaddr[5]) != 6) {
        printf("Error: Invalid MAC address format.\n");
        return;
    }

    // Set the rate and size
    if (rate > 0) {
        crb.bytes_per_sec = rate * 125000;  //mb to bytes
        crb.size = crb.bytes_per_sec;
    }

    // Set direction based on user input
    if (strcmp(direction, "up") == 0) {
        crb.direction = AIR_DIR_UPLINK;
    } else if (strcmp(direction, "down") == 0) {
        crb.direction = AIR_DIR_DOWNLINK;
    } else {
        printf("Error: Invalid direction. Use 'up' or 'down'.\n");
        return;
    }

    // Open the device (assuming /dev/air)
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }

    // Send IOCTL to kernel
    if (ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN_USER, &crb) < 0) {
        perror("ioctl");
        close(fd);
        return;
    }

    printf("Rate limit set: MAC=%s, Rate=%u bytes/sec, Size=%u, Direction=%s\n",
           mac_addr, crb.bytes_per_sec, crb.size, direction);
    close(fd);
}


void cmd_set_wlan_rate_limit(const char *interface, uint32_t rate, const char *direction) 
{
    int wlan_idx; // This should map to the interface's WLAN index
    struct adpi_ratelimit_bucket crb;
    memset(&crb, 0, sizeof(crb));

    wlan_idx = IFNAME_HASH(interface);
    crb.wlan_idx = wlan_idx;

    // Set the rate and size
    if (rate > 0) {
        crb.bytes_per_sec = rate * 125000;  //mb to bytes
        crb.size = crb.bytes_per_sec;
    }

    // Set direction based on user input
    if (strcmp(direction, "up") == 0) {
        crb.direction = AIR_DIR_UPLINK;
    } else if (strcmp(direction, "down") == 0) {
        crb.direction = AIR_DIR_DOWNLINK;
    } else {
        printf("Error: Invalid direction. Use 'up' or 'down'.\n");
        return;
    }

    // Open the device (assuming /dev/air)
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }

    // Send IOCTL to kernel
    if (ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN, &crb) < 0) {
        perror("ioctl");
        close(fd);
        return;
    }

    printf("Rate limit set: Interface=%s, Rate=%u bytes/sec, Size=%u, Direction=%s\n",
           interface, crb.bytes_per_sec, crb.size, direction);
    close(fd);
}


void cmd_get_wlan_rate_limit(const char *ifname) 
{
    struct adpi_ratelimit_bucket bucket = {0};
    int wlan_idx; // This should map to the interface's WLAN index

    wlan_idx = IFNAME_HASH(ifname);
    bucket.wlan_idx = wlan_idx;

    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return;
    }

    for (int dir = 0; dir <= 1; dir++) {
        bucket.direction = dir;

        // Make the IOCTL call
        if (ioctl(fd, IOCTL_ADPI_GET_RATELIMIT_WLAN, &bucket) < 0) {
            perror("IOCTL failed");
            close(fd);
            return;
        }

        // Print the result
        printf("Rate Limit for interface %s (WLAN Index: %d):\n", ifname, wlan_idx);
        printf("  Bytes per second: %u\n", bucket.bytes_per_sec);
        printf("  Bucket size: %u\n", bucket.size);
        printf("  Direction: %s\n", bucket.direction == 0 ? "Upload" : "Download");
    }

    close(fd);
}

void cmd_get_user_rate_limit(const char *mac_str) 
{
    int dev_fd = open("/dev/air", O_RDWR);
    if (dev_fd < 0) {
        perror("Failed to open device");
        return;
    }

    struct adpi_ratelimit_bucket crb = {0};
    unsigned int mac[6];

    // Parse MAC address string into bytes
    if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        printf("Invalid MAC address format: %s\n", mac_str);
        close(dev_fd);
        return;
    }

    for (int i = 0; i < 6; i++) {
        crb.macaddr[i] = (uint8_t)mac[i];
    }

    // Query rate limits for both uplink and downlink directions
    for (int dir = 0; dir <= 1; dir++) {
        crb.direction = dir;

        if (ioctl(dev_fd, IOCTL_ADPI_GET_RATELIMIT_WLAN_USER, &crb) < 0) {
            perror("IOCTL failed");
            close(dev_fd);
            return;
        }

        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x, WLAN Index: %d, Direction: %s\n",
               crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
               crb.macaddr[3], crb.macaddr[4], crb.macaddr[5],
               crb.wlan_idx,
               dir == 0 ? "Uplink" : "Downlink");
        printf("Rate: %u bytes/sec, Bucket Size: %u\n", crb.bytes_per_sec, crb.size);
    }

    close(dev_fd);
}

int cmd_get_all_top_domains()
{
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct adpi_domain_entry *top_domains = malloc(sizeof(struct adpi_domain_entry) * MAX_DOMAINS);
    if (!top_domains) {
        perror("Memory allocation failed");
        close(fd);
        return -1;
    }

    // Perform the ioctl to get the domain entries from the kernel
    if (ioctl(fd, IOCTL_ADPI_GET_AP_TOP_DOMAINS, top_domains) < 0) {
        perror("ioctl failed");
        free(top_domains);
        close(fd);
        return -1;
    }

    // Print the received domain entries
    for (int i = 0; i < MAX_DOMAINS; i++) {
        if (top_domains[i].count > 0) {
            printf("Domain: %s, Count: %u\n", top_domains[i].domain, top_domains[i].count);
        }
    }

    free(top_domains);
    close(fd);
    return 0;
}

// Command implementations
int cmd_get_all_clients() {
    printf("Executing: get_all_clients\n");
    
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    struct adpi_client_info info;
    memset(&info, 0, sizeof(info));


    if (ioctl(fd, IOCTL_ADPI_GET_ALL_CLIENTS, &info) < 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    if (info.count < 0) {
        fprintf(stderr, "Invalid client count: %d\n", info.count);
        close(fd);
        return -1;
    }

    printf("Number of clients: %d\n", info.count);
    for (int i = 0; i < info.count; i++) {
        char ip_str[INET_ADDRSTRLEN];
    
        if (inet_ntop(AF_INET, &info.entry[i].ip, ip_str, sizeof(ip_str)) == NULL) {
            perror("inet_ntop");
        } else {
            printf("Client %d: IP = %s, MAC = %02x:%02x:%02x:%02x:%02x:%02x, Hostname = %s\n",
               i + 1,
               ip_str,  // Dotted-decimal IP format
               info.entry[i].macaddr[0],
               info.entry[i].macaddr[1],
               info.entry[i].macaddr[2],
               info.entry[i].macaddr[3],
               info.entry[i].macaddr[4],
               info.entry[i].macaddr[5],
               info.entry[i].hostname);
        }
    }

    close(fd);
    return 0;
}

void cmd_help() {
    printf("Available Commands:\n");
    printf("  air_cli get_all_clients                                             - List all connected clients\n");
    printf("  air_cli get_all_top_domains                                         - List all top domains\n");
    printf("  air_cli get_user_rate_limit -m 'macaddr'                            - get client based rate limit\n");
    printf("  air_cli get_wlan_rate_limit -i 'interface'                          - get interface based rate limit\n");
    printf("  air_cli set_user_rate_limit -m 'macaddr' -r 'rate' -d 'up/down'     - set client based rate limit\n");
    printf("  air_cli get_wlan_rate_limit -i 'interface' -r 'rate' -d 'up/down'   - set interface based rate limit\n");
    printf("  help                                                               - Show this help message\n");
}

void cmd_exit() {
    printf("Exiting CLI...\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Error: No command provided.\n");
        printf("Type 'help' for a list of available commands.\n");
        return 1;
    }

    // Pass the first argument to the command processor
    process_command(argv[1], argc, argv);

    return 0;
}

