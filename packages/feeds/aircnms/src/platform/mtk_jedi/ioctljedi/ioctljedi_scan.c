#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <unistd.h>
#include <stdint.h>

#include "ioctl80211_jedi.h"
#include "report.h"
#include "log.h"

#define BUFFER_SIZE 4096
#define RTPRIV_IOCTL_GSITESURVEY                                        (SIOCIWFIRSTPRIV + 0x0D)

#define MAX_NETWORKS 50

const char *radio_type_str[] = {
    "None",
    "2G",
    "5G"
};

radio_type_t neighbor_get_radio_type(int channel) 
{
    if ((channel >= 1 && channel <= 14)) {
        return RADIO_TYPE_2G;
    } else if ((channel >= 36 && channel <= 64) || (channel >= 100 && channel <= 165)) {
        return RADIO_TYPE_5G;
    } else if ((channel >= 1 && channel <= 233) || (channel >= 191 && channel <= 253)) {
        return RADIO_TYPE_6G;
    } else {
        return RADIO_TYPE_NONE;
    }
}

void parse_line(const char *line, neighbor_report_data_t *report) 
{
    int index, ssid_length, lparsed;
    char security[32] = {0}, mode[16] = {0}, ext_channel[8] = {0}, nt[4] = {0}, wps[4] = {0}, dpid[4] = {0};
    int signal = 0;
 
    if (report->n_entry >= MAX_NEIGHBOUR) return;
    lparsed = sscanf(line, "%d %d %31s %17s %31s %d %15s %7s %3s %d %3s %3s",
                               &index, &report->record[report->n_entry].channel, report->record[report->n_entry].ssid, report->record[report->n_entry].bssid, 
                               security, &signal, mode, 
                               ext_channel, nt, &ssid_length, wps, dpid);
    report->record[report->n_entry].rssi = signal - 95;
    if (signal - 95 > 0) {
        report->record[report->n_entry].rssi = -95;
    }
    report->record[report->n_entry].radio_type = neighbor_get_radio_type(report->record[report->n_entry].channel);
    if (lparsed >= 11) {
        report->n_entry++;
    } else {
        printf("Warning: Could not parse line: %s\n", line);
    }
}

void parse_buffer(const char *buffer, neighbor_report_data_t *report) 
{
    char *line = strtok((char *)buffer, "\n");  // Tokenize lines
    while (line != NULL) {
        if (strstr(line, "Total=") || strstr(line, "No  Ch  SSID")) {
            line = strtok(NULL, "\n");  // Skip header lines
            continue;
        }
        parse_line(line, report);
        line = strtok(NULL, "\n");
    }
}

void print_networks(neighbor_report_data_t *report) 
{
    LOG(INFO, "Parsed Wi-Fi Networks (%d total) \n", report->n_entry);
    //printf("\nParsed Wi-Fi Networks (%d total):\n", report->n_entry);
    //printf("---------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < report->n_entry; i++) {
        LOG(INFO, "%-3d %-3d %-18s %-17s %-6d\n",
               report->record[i].radio_type, report->record[i].channel, report->record[i].ssid, 
               report->record[i].bssid, report->record[i].rssi);
        //printf("%-3d %-3d %-18s %-17s %-6d\n",
          //     report->record[i].radio_type, report->record[i].channel, report->record[i].ssid, 
            //   report->record[i].bssid, report->record[i].rssi);
    }
}

int get_neighbour_report(char *iface, neighbor_report_data_t *report)
{
    int sockfd;
    struct iwreq wrq;
    char buffer[BUFFER_SIZE] = {0};
    char cmdbuf[64] = {0};

    sprintf(cmdbuf, "iwpriv %s set SiteSurvey=1", iface);
    system(cmdbuf);

    sleep(1);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ);
    wrq.u.data.pointer = buffer;
    wrq.u.data.length = strlen(buffer) + 1;  // Include NULL terminator
    if (ioctl(sockfd, RTPRIV_IOCTL_GSITESURVEY, &wrq) < 0) {  // Example private command
        perror("ioctl(SIOCSIWPRIV)");
        close(sockfd);
        return -1;
    }

    parse_buffer(buffer, report);
    print_networks(report);

    close(sockfd);

    return 0;
}

ioctl_status_t ioctl80211_jedi_scan_results_get(neighbor_report_data_t *report) 
{
    /* 2.4Ghz Neighbour List */
    LOG(INFO, "Scanning 2.4GHZ Neighbour");
    get_neighbour_report("ra0", report);
    /* 5Ghz Neighbour List */
    LOG(INFO, "Scanning 5GHZ Neighbour");
    get_neighbour_report("rax0", report);

    return IOCTL_STATUS_OK;
}



