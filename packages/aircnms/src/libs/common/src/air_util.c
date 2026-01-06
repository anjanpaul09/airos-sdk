#include <stdio.h>
#include <unistd.h>
#include <stdint.h>  
#include <stddef.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "log.h"
#include "memutil.h"
#include "air_util.h" 

#define UCI_BUF_LEN 256

typedef struct {
    char lat[32];
    char lon[32];
    time_t last_updated;
    bool valid;
} location_cache_t;

static location_cache_t g_location_cache = {0};

bool get_location_from_ipinfo(char *lat, size_t lat_size, char *lon, size_t lon_size)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    char request[512];
    char response[4096] = {0};
    ssize_t bytes_received;
    int rv;
    char *body_start;
    char *lat_start, *lon_start;

    if (!lat || !lon || lat_size == 0 || lon_size == 0) {
        fprintf(stderr, "Invalid parameters\n");
        return false;
    }

    // Setup hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP

    // Resolve hostname
    rv = getaddrinfo("ip-api.com", "80", &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(rv));
        return false;
    }

    // Try to connect
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        break; // Successfully connected
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect\n");
        freeaddrinfo(servinfo);
        return false;
    }

    freeaddrinfo(servinfo);

    // Build HTTP GET request
    snprintf(request, sizeof(request),
             "GET /json/ HTTP/1.1\r\n"
             "Host: ip-api.com\r\n"
             "Connection: close\r\n"
             "\r\n");

    // Send request
    if (send(sockfd, request, strlen(request), 0) == -1) {
        fprintf(stderr, "Failed to send request\n");
        close(sockfd);
        return false;
    }

    // Receive response
    size_t total = 0;
    while (total < sizeof(response) - 1) {
        bytes_received = recv(sockfd, response + total, sizeof(response) - total - 1, 0);
        if (bytes_received <= 0) {
            break;
        }
        total += bytes_received;
    }

    close(sockfd);

    if (total == 0) {
        fprintf(stderr, "No response received\n");
        return false;
    }

    response[total] = '\0';

    // Find the body (after "\r\n\r\n")
    body_start = strstr(response, "\r\n\r\n");
    if (body_start == NULL) {
        fprintf(stderr, "Invalid HTTP response\n");
        return false;
    }
    body_start += 4; // Skip "\r\n\r\n"

    // Debug output
    // fprintf(stderr, "Body: %s\n", body_start);

    // Parse latitude
    lat_start = strstr(body_start, "\"lat\"");
    if (lat_start == NULL) {
        fprintf(stderr, "Latitude not found\n");
        return false;
    }
    lat_start = strchr(lat_start, ':');
    if (lat_start == NULL) {
        return false;
    }
    lat_start++;

    // Skip whitespace
    while (*lat_start && isspace(*lat_start)) {
        lat_start++;
    }

    // Extract latitude
    char *lat_end = lat_start;
    while (*lat_end && (isdigit(*lat_end) || *lat_end == '.' || *lat_end == '-')) {
        lat_end++;
    }

    size_t lat_len = lat_end - lat_start;
    if (lat_len == 0 || lat_len >= lat_size) {
        fprintf(stderr, "Invalid latitude\n");
        return false;
    }
    strncpy(lat, lat_start, lat_len);
    lat[lat_len] = '\0';

    // Parse longitude
    lon_start = strstr(body_start, "\"lon\"");
    if (lon_start == NULL) {
        fprintf(stderr, "Longitude not found\n");
        return false;
    }
    lon_start = strchr(lon_start, ':');
    if (lon_start == NULL) {
        return false;
    }
    lon_start++;

    // Skip whitespace
    while (*lon_start && isspace(*lon_start)) {
        lon_start++;
    }

    // Extract longitude
    char *lon_end = lon_start;
    while (*lon_end && (isdigit(*lon_end) || *lon_end == '.' || *lon_end == '-')) {
        lon_end++;
    }

    size_t lon_len = lon_end - lon_start;
    if (lon_len == 0 || lon_len >= lon_size) {
        fprintf(stderr, "Invalid longitude\n");
        return false;
    }
    strncpy(lon, lon_start, lon_len);
    lon[lon_len] = '\0';

    return true;
}

bool get_location_cached(char *lat, size_t lat_size, char *lon, size_t lon_size)
{
    time_t now = time(NULL);

    // Refresh only if cache is invalid or older than 1 hour
    if (!g_location_cache.valid ||
        (now - g_location_cache.last_updated) > 3600) {

        if (!get_location_from_ipinfo(g_location_cache.lat,
                                      sizeof(g_location_cache.lat),
                                      g_location_cache.lon,
                                      sizeof(g_location_cache.lon))) {
            return false;
        }

        g_location_cache.last_updated = now;
        g_location_cache.valid = true;
    }

    // Return cached values
    strncpy(lat, g_location_cache.lat, lat_size - 1);
    lat[lat_size - 1] = '\0';
    strncpy(lon, g_location_cache.lon, lon_size - 1);
    lon[lon_size - 1] = '\0';

    return true;
}

bool get_timezone_from_ipapi(char *timezone, size_t timezone_size)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    char request[512];
    char response[4096] = {0};
    ssize_t bytes_received;
    int rv;
    char *body_start;
    char *tz_start;

    if (!timezone || timezone_size == 0) {
        fprintf(stderr, "Invalid parameters\n");
        return false;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo("ip-api.com", "80", &hints, &servinfo);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(rv));
        return false;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect\n");
        freeaddrinfo(servinfo);
        return false;
    }

    freeaddrinfo(servinfo);

    snprintf(request, sizeof(request),
             "GET /json/ HTTP/1.1\r\n"
             "Host: ip-api.com\r\n"
             "Connection: close\r\n"
             "\r\n");

    if (send(sockfd, request, strlen(request), 0) == -1) {
        fprintf(stderr, "Failed to send request\n");
        close(sockfd);
        return false;
    }

    size_t total = 0;
    while (total < sizeof(response) - 1) {
        bytes_received = recv(sockfd, response + total, sizeof(response) - total - 1, 0);
        if (bytes_received <= 0) break;
        total += bytes_received;
    }

    close(sockfd);

    if (total == 0) {
        fprintf(stderr, "No response received\n");
        return false;
    }

    response[total] = '\0';

    body_start = strstr(response, "\r\n\r\n");
    if (body_start == NULL) {
        fprintf(stderr, "Invalid HTTP response\n");
        return false;
    }
    body_start += 4;

    // Parse timezone from JSON: "timezone":"America/Chicago"
    tz_start = strstr(body_start, "\"timezone\"");
    if (tz_start == NULL) {
        fprintf(stderr, "Timezone not found\n");
        return false;
    }

    // Find the value after the colon
    tz_start = strchr(tz_start, ':');
    if (tz_start == NULL) return false;
    tz_start++;

    // Skip whitespace and opening quote
    while (*tz_start && (isspace(*tz_start) || *tz_start == '"')) {
        tz_start++;
    }

    // Find closing quote
    char *tz_end = strchr(tz_start, '"');
    if (tz_end == NULL) {
        fprintf(stderr, "Malformed timezone value\n");
        return false;
    }

    size_t tz_len = tz_end - tz_start;
    if (tz_len == 0 || tz_len >= timezone_size) {
        fprintf(stderr, "Invalid timezone length\n");
        return false;
    }

    strncpy(timezone, tz_start, tz_len);
    timezone[tz_len] = '\0';

    return true;
}

int get_fw_version(char *version_buf, size_t buf_size) 
{
    FILE *file;
    char *newline;

    file = fopen(VERSION_FILE, "r");
    if (file == NULL) {
        perror("Failed to open version file");
        return -1;
    }

    if (fgets(version_buf, buf_size, file) == NULL) {
        perror("Failed to read version from file");
        fclose(file);
        return -1;
    }

    fclose(file);

    newline = strchr(version_buf, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }

    return 0;
}

void error(const char *msg) {
    perror(msg);
}

bool get_public_ip(char *public_ip)
{
    static time_t last_check = 0;
    static char cached_ip[MAX_IP_LEN] = "0.0.0.0";

    time_t now = time(NULL);
    if (now - last_check < 60) {  // Cache valid for 10 seconds
        strcpy(public_ip, cached_ip);
        return true;
    }

    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[1024];

    strcpy(public_ip, "0.0.0.0");

    // Resolve host
    server = gethostbyname(HOST);
    if (!server) {
        perror("gethostbyname");
        return false;
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    // Prepare address
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Connect
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return false;
    }

    // Use poll to send request
    struct pollfd pfd = {.fd = sockfd, .events = POLLOUT};
    if (poll(&pfd, 1, TIMEOUT_MS) <= 0) {
        perror("poll write timeout");
        close(sockfd);
        return false;
    }

    // Send HTTP GET request
    if (write(sockfd, REQUEST, strlen(REQUEST)) < 0) {
        perror("write");
        close(sockfd);
        return false;
    }

    // Switch to POLLIN to wait for response
    pfd.events = POLLIN;
    int total = 0;
    char response[2048] = {0};

    while (1) {
        int ret = poll(&pfd, 1, TIMEOUT_MS);
        if (ret < 0) {
            perror("poll read error");
            break;
        } else if (ret == 0) {
            fprintf(stderr, "Timeout reading from server\n");
            break;
        }

        if (pfd.revents & POLLIN) {
            int n = read(sockfd, buffer, sizeof(buffer) - 1);
            if (n <= 0) break;
            if (total + n >= sizeof(response) - 1) break;
            memcpy(response + total, buffer, n);
            total += n;
            response[total] = '\0';
        }
    }

    close(sockfd);

    // Parse IP from body (after "\r\n\r\n")
    char *ip_start = strstr(response, "\r\n\r\n");
    if (ip_start) {
        ip_start += 4;
        strncpy(public_ip, ip_start, MAX_IP_LEN - 1);
        public_ip[strcspn(public_ip, "\r\n")] = 0; // Strip newlines

        // ✅ Update cache
        strncpy(cached_ip, public_ip, MAX_IP_LEN - 1);
        cached_ip[MAX_IP_LEN - 1] = '\0';
        last_check = now;

        return true;
    }

    return false;
}

int set_fw_id_to_aircnms(char *fw_id)
{
    int rc;
    char cmd[256];

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].fw_id=%s", fw_id);
    rc = system(cmd);

    rc = system("uci commit aircnms");

    return rc;
}

int get_fw_id_frm_aircnms(char *fw_id) 
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].fw_id", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
    }
    sscanf(buf, "%s", fw_id);

    return 0;
}

int set_fw_upgrade_status_to_aircnms(event_status status)
{
    int rc;
    char cmd[256];
    int fw_status = 0;
    
    if (status == UPGRADING) { 
        fw_status = 1;
    } else if (status == UPGRADED) {
        fw_status = 0;
    }
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].fw_upgrading_status=%d", fw_status);
    rc = system(cmd);

    rc = system("uci commit aircnms");

    return rc;

}

int check_fw_upgrade_status()
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    int status = 0;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].fw_upgrading_status", buf, (size_t)UCI_BUF_LEN);

    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
        return 0; 
    }

    status = atoi(buf);

    return status;
}

bool air_set_online_status(int status)
{
    int rc;
    char cmd[256];

    memset(cmd, 0, sizeof(cmd));
    int ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].online=%d", status);
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for online status (ret=%d)", ret);
        return false;
    }
    rc = system(cmd);
    if (rc != 0) {
        LOG(ERR, "Failed to set online status: command returned %d", rc);
        return false;
    }
    rc = system("uci commit aircnms");
    if (rc != 0) {
        LOG(ERR, "Failed to commit UCI changes: command returned %d", rc);
        return false;
    }

    return true;
}

int air_check_online_status()
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int status = 0;

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].online", buf, (size_t)UCI_BUF_LEN);

    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
        return 0; 
    }

    status = atoi(buf);

    return status;
}
