#ifndef AIR_UTIL_H
#define AIR_UTIL_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>

#include "log.h"
#include "memutil.h"
#define DATA_BUFFER_SIZE 10240
#define MAX_IP_LEN 16
#define HOST "ifconfig.me"
#define PORT 80
//#define REQUEST "GET / HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n"
#define REQUEST "GET /ip HTTP/1.1\r\n" \
                "Host: " HOST "\r\n"      \
                "Connection: close\r\n\r\n"
#define VERSION_FILE "/etc/version"
#define TIMEOUT_MS 2000  // 2 seconds timeout

typedef enum {
    UPGRADE = 1,
    ALARM,
    CMD
} event_type;

typedef enum {
    DOWNLOADED = 1,
    UPGRADING,
    UPGRADED,
    FAILED,
    REBOOT
} event_status;

typedef struct {
    event_type type;
    event_status status;
    char data[DATA_BUFFER_SIZE];
    char reason[264];
    char cloud_id[128];
} event_info;

int set_fw_id_to_aircnms(char *fw_id);
int check_fw_upgrade_status(void);
int set_fw_upgrade_status_to_aircnms(event_status status);
int get_fw_id_frm_aircnms(char *fw_id); 
int get_fw_version(char *version_buf, size_t buf_size); 
bool get_public_ip(char *public_ip);
bool get_location_cached(char *lat, size_t lat_size, char *lon, size_t lon_size);
bool get_location_from_ipinfo(char *lat, size_t lat_size, char *lon, size_t lon_size);
bool get_timezone_from_ipapi(char *timezone, size_t timezone_size);

#endif // AIR_UTIL_H
