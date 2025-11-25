#include <stdio.h>
#include <unistd.h>
#include <stdint.h>  
#include <stddef.h>
#include <poll.h>

#include "log.h"
#include "memutil.h"
#include "air_util.h" 

#define UCI_BUF_LEN 256

bool get_location_from_ipinfo(char *lat, size_t lat_size, char *lon, size_t lon_size)
{
    FILE *fp;
    char buffer[1024] = {0};
    char *result = NULL;
    char *lat_start = NULL;
    char *lon_start = NULL;
    char *lat_end = NULL;
    char *lon_end = NULL;
    
    if (!lat || !lon || lat_size == 0 || lon_size == 0) {
        fprintf(stderr, "Invalid parameters\n");
        return false;
    }
    
    // Execute curl command to get location
    fp = popen("curl -s --connect-timeout 5 --max-time 10 http://ip-api.com/json 2>/dev/null", "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to execute curl command\n");
        return false;
    }
    
    // Read the response
    result = fgets(buffer, sizeof(buffer), fp);
    pclose(fp);
    
    if (result == NULL || strlen(buffer) == 0) {
        fprintf(stderr, "Failed to read curl response\n");
        return false;
    }
    
    // Parse latitude from JSON
    lat_start = strstr(buffer, "\"lat\":");
    if (lat_start == NULL) {
        fprintf(stderr, "Latitude not found in response\n");
        return false;
    }
    lat_start += 6; // Skip "lat":
    
    // Find the end of latitude value (comma or closing brace)
    lat_end = lat_start;
    while (*lat_end && *lat_end != ',' && *lat_end != '}') {
        lat_end++;
    }
    
    // Copy latitude
    size_t lat_len = lat_end - lat_start;
    if (lat_len >= lat_size) {
        lat_len = lat_size - 1;
    }
    strncpy(lat, lat_start, lat_len);
    lat[lat_len] = '\0';
    
    // Parse longitude from JSON
    lon_start = strstr(buffer, "\"lon\":");
    if (lon_start == NULL) {
        fprintf(stderr, "Longitude not found in response\n");
        return false;
    }
    lon_start += 6; // Skip "lon":
    
    // Find the end of longitude value
    lon_end = lon_start;
    while (*lon_end && *lon_end != ',' && *lon_end != '}') {
        lon_end++;
    }
    
    // Copy longitude
    size_t lon_len = lon_end - lon_start;
    if (lon_len >= lon_size) {
        lon_len = lon_size - 1;
    }
    strncpy(lon, lon_start, lon_len);
    lon[lon_len] = '\0';
    
    // Validate that we got both values
    if (strlen(lat) == 0 || strlen(lon) == 0) {
        fprintf(stderr, "Empty latitude or longitude\n");
        return false;
    }
    
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

