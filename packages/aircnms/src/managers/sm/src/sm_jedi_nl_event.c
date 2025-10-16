#include <limits.h>
#include <stdio.h>
//#include <signal.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/wireless.h>


#include <stdint.h>  
#include "airdpi/air_ioctl.h"
#include "os_time.h"
#include "os_nif.h"
//#include "dppline.h"
#include "log.h"

#include "qm_conn.h"
#include "sm.h"

#define SM_NL_EV_INTERVAL 1.0

int sock;  // Global socket descriptor
ev_io netlink_watcher;
static struct ev_timer  sm_nlev_timer;
static double           sm_nlev_timer_interval = SM_NL_EV_INTERVAL;
//static uint8_t          sm_nlev_buf[1024];

#define BUFFER_SIZE 8192

enum {
    DRVEVNT_FIRST_ID = 0,
    WHC_DRVEVNT_STA_PROBE_REQ,
    WHC_DRVEVNT_AP_PROBE_RSP,
    WHC_DRVEVNT_STA_JOIN,
    WHC_DRVEVNT_STA_LEAVE,
    WHC_DRVEVNT_EXT_UPLINK_STAT,
    WHC_DRVEVNT_STA_TIMEOUT,
    WHC_DRVEVNT_STA_AUTH_REJECT,
    WHC_DRVEVNT_CHANNEL_LOAD_REPORT,
    WHC_DRVEVNT_STA_RSSI_TOO_LOW,
    WHC_DRVEVNT_STA_ACTIVITY_STATE,
    DRVEVNT_END_ID,
};

#define OID_WAPP_EVENT                              0x0647
#define OID_WAPP_EVENT2                             0x09B4
#define OID_802_11_MBO_MSG                          0x0953


#define RT_ASSOC_EVENT_FLAG                         0x0101
#define RT_DISASSOC_EVENT_FLAG                      0x0102
#define RT_REQIE_EVENT_FLAG                         0x0103
#define RT_RESPIE_EVENT_FLAG                        0x0104
#define RT_ASSOCINFO_EVENT_FLAG                     0x0105
#define RT_PMKIDCAND_FLAG                           0x0106
#define RT_INTERFACE_DOWN                           0x0107
#define RT_INTERFACE_UP                             0x0108

#define MAC_ADDR_LEN 6
#define CUSTOM_IE_TOTAL_LEN 128

struct drvEventStaJoin {
    uint16_t type;                                        /* WHC_DRVEVNT_STA_JOIN */
    uint8_t sta_mac[MAC_ADDR_LEN];                /* Station's MAC address */
    uint8_t channel;                                          /* Wireless channel that receive this frame. */
    uint32_t aid;                                         /* Station's association ID */
    uint8_t custom_ie_len;                                /* Length of custom vendor information element */
    uint8_t custom_ie[CUSTOM_IE_TOTAL_LEN];   /* Content of custom vendor information element */
    uint32_t capability;
};

bool sm_ext_event_trigger_report_request(radio_entry_t *radio_cfg, sm_stats_request_t *request);

void sm_nlev_get_curr_client(void)
{
    kill(getpid(), SIGUSR1);
}


int sm_add_client_entry(uint8_t *sta_mac)
{
    /*
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }

    struct adpi_add_sta_entry entry;
    memcpy(entry.macaddr, sta_mac, 6);

    if (ioctl(fd, IOCTL_ADPI_STA_ADD_ENTRY, &entry) < 0) {
        perror("IOCTL failed");
        close(fd);
        return -1;
    }

    close(fd);
    */
    sm_nlev_get_curr_client();
    return 0;
}

int sm_remove_client_entry(uint8_t *sta_mac)
{
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return -1;
    }

    struct adpi_del_sta_entry entry;
    memcpy(entry.macaddr, sta_mac, 6);

    if (ioctl(fd, IOCTL_ADPI_STA_DEL_ENTRY, &entry) < 0) {
        perror("IOCTL failed");
        close(fd);
        return -1;
    }

    close(fd);
    sm_nlev_get_curr_client();
    return 0;
}


void nlParseMtkWifiEvents(int event, char *data, int len)
{
    char outbuf[512];

    switch (event) {
        case WHC_DRVEVNT_STA_PROBE_REQ: {
        } break;
        case WHC_DRVEVNT_AP_PROBE_RSP: {
        } break;
        case WHC_DRVEVNT_STA_JOIN: {
            uint8_t sta_mac[MAC_ADDR_LEN];

            memcpy(sta_mac, data, 6);
            memset(outbuf, 0, sizeof(outbuf));
            sprintf(outbuf, "MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
                                        sta_mac[0], sta_mac[1],
                                        sta_mac[2], sta_mac[3],
                                        sta_mac[4], sta_mac[5]);
            sm_add_client_entry(sta_mac);
        } break;
        case WHC_DRVEVNT_STA_LEAVE: {
            uint8_t sta_mac[MAC_ADDR_LEN];

            memcpy(sta_mac, data, 6);
            memset(outbuf, 0, sizeof(outbuf));
            sprintf(outbuf, "MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
                                        sta_mac[0], sta_mac[1],
                                        sta_mac[2], sta_mac[3],
                                        sta_mac[4], sta_mac[5]);
            sm_remove_client_entry(sta_mac);
        } break;
        case WHC_DRVEVNT_EXT_UPLINK_STAT: {
        } break;
        case WHC_DRVEVNT_STA_TIMEOUT: {
        } break;
        case WHC_DRVEVNT_STA_AUTH_REJECT: {
        } break;
        case WHC_DRVEVNT_CHANNEL_LOAD_REPORT: {
        } break;
        case WHC_DRVEVNT_STA_RSSI_TOO_LOW: {
        } break;
        case WHC_DRVEVNT_STA_ACTIVITY_STATE: {
        } break;
        case RT_ASSOC_EVENT_FLAG: {
        } break;
        case RT_DISASSOC_EVENT_FLAG: {
        } break;
        case RT_REQIE_EVENT_FLAG: {
        } break;
        case RT_RESPIE_EVENT_FLAG: {
        } break;
        case RT_ASSOCINFO_EVENT_FLAG: {
        } break;
        case RT_PMKIDCAND_FLAG: {
        } break;
        case RT_INTERFACE_DOWN: {
        } break;
        case OID_802_11_MBO_MSG: {
        } break;
        case OID_WAPP_EVENT: {
        } break;
        default: {
           printf("Event not registered  %s %d\n", __func__, __LINE__);
        }
    }

    return;
}

void parse_netlink_msg(struct nlmsghdr *h, int len)
{
    char ifname[IFNAMSIZ] = {0};  // Interface name buffer

    while (NLMSG_OK(h, len)) {
        if (NLMSG_PAYLOAD(h, 0) >= sizeof(struct ifinfomsg)) {
            struct rtattr *attr = (struct rtattr *)((char *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)));
            int attrlen = NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg));
            int rlen = RTA_ALIGN(sizeof(struct rtattr));

            while (RTA_OK(attr, attrlen)) {
                struct iw_event iwe;
                char *start;
                char *end;

                // ✅ Extract Interface Name
                if (attr->rta_type == IFLA_IFNAME) {
                    int ilen = attr->rta_len - rlen;
                    if (ilen > sizeof(ifname) - 1) {
                        printf("Interface name exceeds length\n");
                        break;
                    }
                    memcpy(ifname, RTA_DATA(attr), ilen);
                    ifname[ilen] = '\0';  // ✅ Proper null-termination
                }

                // ✅ Skip if not wireless
                if (attr->rta_type != IFLA_WIRELESS) {
                    attr = RTA_NEXT(attr, attrlen);
                    continue;
                }

                start = ((char *)attr) + rlen;
                end = start + (attr->rta_len - rlen);

                while (start + IW_EV_LCP_LEN <= end) {
                    memcpy(&iwe, start, IW_EV_LCP_LEN);
                    if (iwe.len <= IW_EV_LCP_LEN) {
                        break;
                    }

                    if (iwe.cmd == IWEVCUSTOM || iwe.cmd == IWEVGENIE) {
                        char *pos = (char *)&iwe.u.data.length;
                        char *data = start + IW_EV_POINT_LEN;
                        memcpy(pos, start + IW_EV_LCP_LEN, sizeof(struct iw_event) - (pos - (char *)&iwe));

                        if (data + iwe.u.data.length <= end) {
                            nlParseMtkWifiEvents(iwe.u.data.flags, data, iwe.u.data.length);
                        }
                    }
                    start += iwe.len;
                }
                attr = RTA_NEXT(attr, attrlen);
            }
        }
        h = NLMSG_NEXT(h, len);
    }
}

/* Netlink event handler */
static void netlink_cb(struct ev_loop *loop, ev_io *watcher, int revents)
{
    if (revents & EV_READ) {
        char buffer[BUFFER_SIZE];
        struct sockaddr_nl sa;
        struct iovec iov = { buffer, sizeof(buffer) };
        struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

        int len = recvmsg(sock, &msg, 0);
        if (len > 0) {
            parse_netlink_msg((struct nlmsghdr *)buffer, len);
        } else {
            perror("recvmsg");
        }
    }
}

void sm_nlev_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    //printf("Timer triggered: Checking for Netlink events...\n");

    /* Call netlink event handler manually */
    netlink_cb(loop, &netlink_watcher, EV_READ);
    return;
}

bool sm_nl_event_monitor(void)
{
    struct sockaddr_nl sa;

    /* Create Netlink socket */
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    /* Bind Netlink socket */
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sock);
        return false;
    }

    /* Initialize and start Netlink event watcher */
    ev_io_init(&netlink_watcher, netlink_cb, sock, EV_READ);
    ev_io_start(EV_DEFAULT, &netlink_watcher);

    ev_timer_init(&sm_nlev_timer, sm_nlev_timer_handler, sm_nlev_timer_interval, sm_nlev_timer_interval);

    sm_nlev_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &sm_nlev_timer);

    return true;
}

