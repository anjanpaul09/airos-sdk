#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "airioctl.h"
#include "airdpi/air_ioctl.h"

enum {
	AIR_DIR_UPLINK = 0,
	AIR_DIR_DOWNLINK = 1,
};

static int open_air(void)
{
	int fd = open("/dev/air", O_RDWR);
	if (fd < 0)
		perror("open /dev/air");
	return fd;
}

int air_ioctl_block_domain(struct blob_buf *out, const char *domain)
{
	if (!domain) return -1;
	int fd = open_air();
	if (fd < 0) return -1;
	char buf[MAX_DOMAIN_NAME_LEN];
	strncpy(buf, domain, MAX_DOMAIN_NAME_LEN - 1);
	buf[MAX_DOMAIN_NAME_LEN - 1] = '\0';
	int rc = ioctl(fd, IOCTL_ADPI_BLOCK_DOMAIN, buf);
	if (rc < 0) perror("ioctl BLOCK_DOMAIN");
	close(fd);
	return rc;
}

int air_ioctl_unblock_domain(struct blob_buf *out, const char *domain)
{
	if (!domain) return -1;
	int fd = open_air();
	if (fd < 0) return -1;
	char buf[MAX_DOMAIN_NAME_LEN];
	strncpy(buf, domain, MAX_DOMAIN_NAME_LEN - 1);
	buf[MAX_DOMAIN_NAME_LEN - 1] = '\0';
	int rc = ioctl(fd, IOCTL_ADPI_UNBLOCK_DOMAIN, buf);
	if (rc < 0) perror("ioctl UNBLOCK_DOMAIN");
	close(fd);
	return rc;
}

int air_ioctl_set_user_rate_limit(struct blob_buf *out, const char *mac_addr, uint32_t rate, const char *direction)
{
	if (!mac_addr || !direction) return -1;
	struct adpi_ratelimit_bucket b = {0};
	if (sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&b.macaddr[0], &b.macaddr[1], &b.macaddr[2], &b.macaddr[3], &b.macaddr[4], &b.macaddr[5]) != 6)
		return -1;
	if (rate > 0) {
		b.bytes_per_sec = rate * 125000;
		b.size = b.bytes_per_sec;
	}
	if (strcmp(direction, "up") == 0) b.direction = AIR_DIR_UPLINK;
	else if (strcmp(direction, "down") == 0) b.direction = AIR_DIR_DOWNLINK;
	else return -1;
	int fd = open_air();
	if (fd < 0) return -1;
	int rc = ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN_USER, &b);
	if (rc < 0) perror("ioctl RATELIMIT_WLAN_USER");
	close(fd);
	return rc;
}

int air_ioctl_set_wlan_rate_limit(struct blob_buf *out, const char *interface, uint32_t rate, const char *direction)
{
	if (!interface || !direction) return -1;
	struct adpi_ratelimit_bucket b = {0};
	b.wlan_idx = IFNAME_HASH(interface);
	if (rate > 0) {
		b.bytes_per_sec = rate * 125000;
		b.size = b.bytes_per_sec;
	}
	if (strcmp(direction, "up") == 0) b.direction = AIR_DIR_UPLINK;
	else if (strcmp(direction, "down") == 0) b.direction = AIR_DIR_DOWNLINK;
	else return -1;
	int fd = open_air();
	if (fd < 0) return -1;
	int rc = ioctl(fd, IOCTL_ADPI_RATELIMIT_WLAN, &b);
	if (rc < 0) perror("ioctl RATELIMIT_WLAN");
	close(fd);
	return rc;
}

int air_ioctl_get_wlan_rate_limit(struct blob_buf *out, const char *ifname)
{
	if (!ifname) return -1;
	struct adpi_ratelimit_bucket b = {0};
	b.wlan_idx = IFNAME_HASH(ifname);
	int fd = open_air();
	if (fd < 0) return -1;
        void *array = blobmsg_open_array(out, "rate_limits");
	for (int dir = 0; dir <= 1; dir++) {
		b.direction = dir;
		if (ioctl(fd, IOCTL_ADPI_GET_RATELIMIT_WLAN, &b) < 0) {
			perror("ioctl GET_RATELIMIT_WLAN");
			close(fd);
                        blobmsg_close_array(out, array);
			return -1;
		}
                void *entry = blobmsg_open_table(out, NULL);

                blobmsg_add_string(out, "ifname", ifname);
                blobmsg_add_string(out, "direction", dir == 0 ? "upload" : "download");

                blobmsg_add_u32(out, "rate_limit_kbps", b.bytes_per_sec ? b.bytes_per_sec : 0);

                blobmsg_close_table(out, entry);
	}
        blobmsg_close_array(out, array);

	close(fd);
	return 0;
}

int air_ioctl_get_user_rate_limit(struct blob_buf *out, const char *mac_str)
{
	if (!mac_str) return -1;
	struct adpi_ratelimit_bucket b = {0};
	unsigned int mac[6];
	if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
				&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++) b.macaddr[i] = (uint8_t)mac[i];
	int fd = open_air();
	if (fd < 0) return -1;
       
        //printf("DEBUG: MAC = %s\n", mac_str);

        void *array = blobmsg_open_array(out, "rate_limits");
	for (int dir = 0; dir <= 1; dir++) {
		b.direction = dir;
		if (ioctl(fd, IOCTL_ADPI_GET_RATELIMIT_WLAN_USER, &b) < 0) {
			perror("ioctl GET_RATELIMIT_WLAN_USER");
			close(fd);
                        blobmsg_close_array(out, array);
			return -1;
                        //continue;
		}

                        // 🧠 Print what the kernel returned
        //printf("DEBUG: ioctl() returned for direction=%d\n", dir);
        //printf("       mac = %02X:%02X:%02X:%02X:%02X:%02X\n",
          //     b.macaddr[0], b.macaddr[1], b.macaddr[2],
            //   b.macaddr[3], b.macaddr[4], b.macaddr[5]);
        //printf("       bytes_per_sec = %u\n", b.bytes_per_sec);
        //printf("       size          = %u\n", b.size);
        //printf("       wlan_idx      = %d\n", b.wlan_idx);
        //printf("       direction     = %d\n", b.direction);
                // Add entry for this direction
                void *entry = blobmsg_open_table(out, NULL);

                blobmsg_add_string(out, "mac", mac_str);
                blobmsg_add_string(out, "direction", dir == 0 ? "upload" : "download");

                blobmsg_add_u32(out, "rate_limit_kbps", b.bytes_per_sec ? b.bytes_per_sec : 0);

                //blobmsg_add_u32(out, "rate_limit_kbps", b.bytes_per_sec);

                blobmsg_close_table(out, entry);
	}
        blobmsg_close_array(out, array);
	close(fd);
	return 0;
}

int air_ioctl_get_all_top_domains(struct blob_buf *out)
{
	int fd = open_air();
	if (fd < 0) return -1;
	struct adpi_domain_entry *top = malloc(sizeof(*top) * MAX_DOMAINS);
	if (!top) {
		close(fd);
		return -1;
	}
	int rc = ioctl(fd, IOCTL_ADPI_GET_AP_TOP_DOMAINS, top);
	if (rc < 0) perror("ioctl GET_AP_TOP_DOMAINS");
	close(fd);

            void *array = blobmsg_open_array(out, "top_domains");

    for (int i = 0; i < MAX_DOMAINS; i++) {
        void *table = blobmsg_open_table(out, NULL);

        // Domain name
        blobmsg_add_string(out, "domain", top[i].domain);

        // Count (convert to host endian if necessary)
        uint32_t count = ntohl(top[i].count); // MIPS little-endian safety
        blobmsg_add_u32(out, "count", count);

        blobmsg_close_table(out, table);
    }

    blobmsg_close_array(out, array);

	free(top);
	return rc;
}

int air_ioctl_get_all_clients(struct blob_buf *out)
{
	int fd = open_air();
	if (fd < 0) return -1;
	struct adpi_client_info info = {0};
	int rc = ioctl(fd, IOCTL_ADPI_GET_ALL_CLIENTS, &info);
	if (rc < 0) perror("ioctl GET_ALL_CLIENTS");
	close(fd);

    void *array = blobmsg_open_array(out, "clients");
    for (int i = 0; i < info.count; i++) {
        struct adpi_client_entry *e = &info.entry[i];
        void *table = blobmsg_open_table(out, NULL);

        // Convert MAC address to string
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 e->macaddr[0], e->macaddr[1], e->macaddr[2],
                 e->macaddr[3], e->macaddr[4], e->macaddr[5]);
        blobmsg_add_string(out, "mac", mac_str);

        // Convert IP to dotted decimal safely
        uint32_t ip = ntohl(e->ip);  // convert from little-endian to host
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF,
                 (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF,
                 ip & 0xFF);
        blobmsg_add_string(out, "ip", ip_str);

        // Add hostname
        blobmsg_add_string(out, "hostname", e->hostname);

        blobmsg_close_table(out, table);
    }
    blobmsg_close_array(out, array);

	return rc;
}


