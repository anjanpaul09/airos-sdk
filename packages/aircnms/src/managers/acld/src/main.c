/*
 * PCAP Reader Application
 * 
 * Minimal standalone application to capture from network interface and extract
 * app and website details from DNS packets.
 * 
 * Based on fsm_lib_test from dns_capture_app.c and dns_monitor_plugin.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/select.h>
#include <ev.h>
#include "dns.h"
#include "app_monitor.h"

/* WAN interface name - can be overridden at compile time */
#ifndef WAN_INTERFACE
#define WAN_INTERFACE "wan"
#endif

/* Statistics */
struct stats {
    int total_packets;
    int dns_queries;
    int dns_responses;
    int parsed_packets;
    int error_packets;
};

/* Configuration structure */
struct capture_config {
    char *interface;
    char *filter;
    int promiscuous;
    int timeout;
    int snaplen;
};

/* Interface handle structure */
struct interface_handle {
    char name[64];
    pcap_t *pcap_handle;
    pthread_t thread_id;
    int active;
    struct capture_config config;
};

#define MAX_INTERFACES 32
static struct interface_handle g_interfaces[MAX_INTERFACES];
static int g_interface_count = 0;
static struct stats g_stats = {0};
static int g_verbose = 0;
static int g_running = 1;
static struct app_monitor g_app_monitor;
static int g_report_interval = 10;  /* Default 10 seconds */
static struct ev_loop *g_ev_loop = NULL;
static struct ev_timer g_report_timer;

/* Periodic report callback */
static void periodic_report_callback(struct ev_loop *loop, ev_timer *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;
    
    printf("\n=== Top 10 Applications by Usage (every %d seconds) ===\n", g_report_interval);
    app_monitor_print_top10(&g_app_monitor);
    printf("========================================================\n\n");
    fflush(stdout);
}

/* Signal handler for graceful shutdown */
void signal_handler(int sig)
{
    (void)sig;
    printf("\nReceived signal, shutting down...\n");
    g_running = 0;
    
    /* Stop periodic timer */
    if (g_ev_loop) {
        ev_timer_stop(g_ev_loop, &g_report_timer);
        ev_break(g_ev_loop, EVBREAK_ALL);
    }
    
    /* Break loop on all active interfaces */
    for (int i = 0; i < g_interface_count; i++) {
        if (g_interfaces[i].active && g_interfaces[i].pcap_handle) {
            pcap_breakloop(g_interfaces[i].pcap_handle);
        }
    }
}


/* Packet handler callback for pcap */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, 
                    const u_char *packet)
{
    struct interface_handle *if_handle = (struct interface_handle *)args;
    struct app_data app_data = {0};
    struct timeval tv;
    int ret;
    
    g_stats.total_packets++;
    
    /* Prepare timestamp */
    if (header->ts.tv_sec > 0) {
        app_data.timestamp = header->ts.tv_sec;
    } else {
        gettimeofday(&tv, NULL);
        app_data.timestamp = tv.tv_sec;
    }
    
    /* Try to parse as DNS packet */
    ret = dns_parse_packet(if_handle->pcap_handle, packet, header->caplen, &app_data);
    
    if (ret == 0) {
        g_stats.parsed_packets++;
        
        if (app_data.is_query) {
            g_stats.dns_queries++;
            /* DNS queries are only for domain mapping, not usage tracking */
        } else {
            g_stats.dns_responses++;
            
            /* Extract IP addresses from DNS response and create IP-to-domain mappings */
            if (app_data.domain[0] != '\0' && app_data.ip_count > 0) {
                for (int i = 0; i < app_data.ip_count; i++) {
                    /* Add IP to domain mapping */
                    app_monitor_add_ip_mapping(&g_app_monitor, app_data.resolved_ips[i], app_data.domain);
                }
            }
        }
    } else {
        /* Parse as IP packet for traffic tracking (non-DNS) */
        struct iphdr *ip_hdr;
        int ip_offset = 0;
        int datalink = pcap_datalink(if_handle->pcap_handle);
        
        /* Determine IP header offset */
        if (datalink == DLT_EN10MB) {
            if (header->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                g_stats.error_packets++;
                return;
            }
            struct ethhdr *eth_hdr = (struct ethhdr *)packet;
            if (ntohs(eth_hdr->h_proto) == ETH_P_IP) {
                ip_offset = sizeof(struct ethhdr);
            } else {
                g_stats.error_packets++;
                return;
            }
        } else if (datalink == DLT_LINUX_SLL) {
            if (header->caplen < 16 + sizeof(struct iphdr)) {
                g_stats.error_packets++;
                return;
            }
            if (ntohs(*(uint16_t *)(packet + 14)) == ETH_P_IP) {
                ip_offset = 16;
            } else {
                g_stats.error_packets++;
                return;
            }
        } else {
            ip_offset = 0;
        }
        
        ip_hdr = (struct iphdr *)(packet + ip_offset);
        
        /* Check if it's IPv4 */
        if (ip_hdr->version == 4) {
            uint32_t src_ip = ntohl(ip_hdr->saddr);  /* Convert to host byte order */
            uint32_t dst_ip = ntohl(ip_hdr->daddr);  /* Convert to host byte order */
            uint16_t total_len = ntohs(ip_hdr->tot_len);
            
            /* Check if IP is in private network range (now in host byte order) */
            int src_is_private = ((src_ip & 0xFFFF0000) == 0xC0A80000) ||  /* 192.168.x.x */
                                 ((src_ip & 0xFF000000) == 0x0A000000) ||   /* 10.x.x.x */
                                 ((src_ip & 0xFFF00000) == 0xAC100000);     /* 172.16-31.x.x */
            
            int dst_is_private = ((dst_ip & 0xFFFF0000) == 0xC0A80000) ||  /* 192.168.x.x */
                                  ((dst_ip & 0xFF000000) == 0x0A000000) ||   /* 10.x.x.x */
                                  ((dst_ip & 0xFFF00000) == 0xAC100000);     /* 172.16-31.x.x */
            
            /* When monitoring WAN interface:
             * - Traffic FROM private (LAN) TO public (WAN) = TX (upload from client)
             * - Traffic FROM public (WAN) TO private (LAN) = RX (download to client)
             */
            if (src_is_private && !dst_is_private) {
                /* TX: Client (private) -> Server (public) */
                /* Pass IP in host byte order (same as stored in DNS mapping) */
                app_monitor_update_usage_from_ip(&g_app_monitor, dst_ip, total_len, 0);
            } else if (!src_is_private && dst_is_private) {
                /* RX: Server (public) -> Client (private) */
                /* Pass IP in host byte order (same as stored in DNS mapping) */
                app_monitor_update_usage_from_ip(&g_app_monitor, src_ip, 0, total_len);
            }
        } else {
            g_stats.error_packets++;
        }
    }
}

void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("DNS Traffic Capture - Extract app and website details from network interface\n\n");
    printf("Options:\n");
    printf("  -i, --interface IF   Interface to capture on (default: auto-detect WAN)\n");
    printf("  -f, --filter FILTER  BPF filter (default: \"ip\")\n");
    printf("  -s, --snaplen SIZE   Snapshot length (default: 1500)\n");
    printf("  -t, --timeout MS     Read timeout in ms (default: 100)\n");
    printf("  -P, --promiscuous    Enable promiscuous mode\n");
    printf("  -v, --verbose        Enable verbose output\n");
    printf("  -m, --monitor        Enable application usage monitoring\n");
    printf("  -r, --report SEC     Report interval in seconds (default: 10)\n");
    printf("  -h, --help           Show this help\n");
    printf("  -l, --list           List available interfaces\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -i eth0                    # Capture DNS on eth0\n", prog_name);
    printf("  %s -i br-lan -f \"udp port 53\" # Capture DNS on br-lan\n", prog_name);
    printf("  %s -i any -v                  # Capture on any interface with verbose\n", prog_name);
    printf("\n");
    printf("Note: This is a minimal implementation. It can be enhanced to:\n");
    printf("  - Extract more DNS details (answers, RR types)\n");
    printf("  - Track application usage patterns (use -m option)\n");
    printf("  - Generate reports and statistics\n");
    printf("  - Support filtering and aggregation\n");
    printf("\n");
    printf("Application Monitoring:\n");
    printf("  Use -m option to enable top 10 application usage tracking\n");
    printf("  Output format: application   usage(MB)\n");
}

void list_interfaces(void)
{
    pcap_if_t *interfaces, *interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    
    printf("Available network interfaces:\n");
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        printf("Error finding interfaces: %s\n", errbuf);
        return;
    }
    
    for (interface = interfaces; interface; interface = interface->next) {
        printf("  %d. %s", ++i, interface->name);
        if (interface->description) {
            printf(" (%s)", interface->description);
        }
        printf("\n");
    }
    
    if (i == 0) {
        printf("  No interfaces found!\n");
    }
    
    pcap_freealldevs(interfaces);
}

/* Find WAN interface using defined WAN_INTERFACE */
int find_wan_interface(void)
{
    pcap_if_t *interfaces, *interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        printf("Error finding interfaces: %s\n", errbuf);
        return 0;
    }
    
    /* Look for the defined WAN interface */
    for (interface = interfaces; interface; interface = interface->next) {
        if (strcmp(interface->name, WAN_INTERFACE) == 0) {
            strncpy(g_interfaces[0].name, interface->name, sizeof(g_interfaces[0].name) - 1);
            g_interfaces[0].name[sizeof(g_interfaces[0].name) - 1] = '\0';
            g_interfaces[0].active = 0;
            count = 1;
            break;
        }
    }
    
    pcap_freealldevs(interfaces);
    return count;
}

/* Find all interfaces starting with "phy" */
int find_phy_interfaces(void)
{
    pcap_if_t *interfaces, *interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        printf("Error finding interfaces: %s\n", errbuf);
        return 0;
    }
    
    for (interface = interfaces; interface; interface = interface->next) {
        if (strncmp(interface->name, "phy", 3) == 0) {
            if (count < MAX_INTERFACES) {
                strncpy(g_interfaces[count].name, interface->name, sizeof(g_interfaces[count].name) - 1);
                g_interfaces[count].name[sizeof(g_interfaces[count].name) - 1] = '\0';
                g_interfaces[count].active = 0;
                count++;
            }
        }
    }
    
    pcap_freealldevs(interfaces);
    return count;
}

int setup_packet_capture(struct interface_handle *if_handle)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_prog;
    struct capture_config *config = &if_handle->config;
    int promisc = config->promiscuous;
    
    /* Bridge interfaces often need promiscuous mode to see all traffic */
    if (strncmp(config->interface, "br-", 3) == 0 || 
        strncmp(config->interface, "bridge", 6) == 0) {
        if (!promisc) {
            printf("Note: Bridge interface detected, enabling promiscuous mode\n");
            promisc = 1;
        }
    }
    
    /* Open capture device - use blocking mode like reference */
    if_handle->pcap_handle = pcap_open_live(config->interface, config->snaplen, 
                                            promisc, config->timeout, errbuf);
    if (if_handle->pcap_handle == NULL) {
        printf("Error opening device %s: %s\n", config->interface, errbuf);
        return -1;
    }
    
    /* Check data link type */
    int datalink = pcap_datalink(if_handle->pcap_handle);
    if (datalink != DLT_EN10MB && datalink != DLT_LINUX_SLL) {
        printf("Warning: Device %s doesn't provide Ethernet headers (datalink: %d)\n", 
               config->interface, datalink);
    }
    
    if (g_verbose) {
        printf("%s: Promiscuous mode: %s\n", if_handle->name, promisc ? "enabled" : "disabled");
    }
    
    /* Compile and apply BPF filter */
    if (pcap_compile(if_handle->pcap_handle, &filter_prog, config->filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter '%s' on %s: %s\n", config->filter, if_handle->name, 
               pcap_geterr(if_handle->pcap_handle));
        pcap_close(if_handle->pcap_handle);
        if_handle->pcap_handle = NULL;
        return -1;
    }
    
    if (pcap_setfilter(if_handle->pcap_handle, &filter_prog) == -1) {
        printf("Error setting filter on %s: %s\n", if_handle->name, pcap_geterr(if_handle->pcap_handle));
        pcap_freecode(&filter_prog);
        pcap_close(if_handle->pcap_handle);
        if_handle->pcap_handle = NULL;
        return -1;
    }
    
    pcap_freecode(&filter_prog);
    
    printf("%s: Packet capture setup successful\n", if_handle->name);
    if (g_verbose) {
        printf("%s: Filter: %s, Data link type: %d\n", if_handle->name, config->filter, datalink);
    }
    
    return 0;
}

/* Thread function to capture from one interface */
void *capture_thread(void *arg)
{
    struct interface_handle *if_handle = (struct interface_handle *)arg;
    int ret;
    
    if_handle->active = 1;
    
    /* Process packets */
    ret = pcap_loop(if_handle->pcap_handle, -1, packet_handler, (u_char *)if_handle);
    
    if (ret == -1) {
        printf("%s: Error processing packets: %s\n", if_handle->name, 
               pcap_geterr(if_handle->pcap_handle));
    } else if (ret == -2) {
        if (g_verbose) {
            printf("%s: Packet capture stopped\n", if_handle->name);
        }
    } else if (ret == 0) {
        if (g_verbose) {
            printf("%s: All packets processed\n", if_handle->name);
        }
    }
    
    if_handle->active = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    struct capture_config config = {
        .interface = NULL,  /* NULL means auto-detect phy interfaces */
        .filter = "ip",  /* Capture all IP traffic to track actual usage */
        .promiscuous = 0,
        .timeout = 100,
        .snaplen = 1500
    };
    int ret, opt;
    
    /* Parse command line arguments */
    static struct option long_options[] = {
        {"interface",   required_argument, 0, 'i'},
        {"filter",      required_argument, 0, 'f'},
        {"snaplen",     required_argument, 0, 's'},
        {"timeout",     required_argument, 0, 't'},
        {"promiscuous", no_argument,       0, 'P'},
        {"verbose",     no_argument,       0, 'v'},
        {"report",      required_argument, 0, 'r'},
        {"help",        no_argument,       0, 'h'},
        {"list",        no_argument,       0, 'l'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "i:f:s:t:Pvr:hl", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            config.interface = optarg;
            break;
        case 'f':
            config.filter = optarg;
            break;
        case 's':
            config.snaplen = atoi(optarg);
            break;
        case 't':
            config.timeout = atoi(optarg);
            break;
        case 'P':
            config.promiscuous = 1;
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'r':
            g_report_interval = atoi(optarg);
            if (g_report_interval < 1) {
                g_report_interval = 10;
            }
            break;
        case 'l':
            list_interfaces();
            return 0;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("=== DNS Traffic Capture Application ===\n");
    
    /* If no interface specified, use WAN interface */
    if (config.interface == NULL) {
        printf("Using WAN interface: %s\n", WAN_INTERFACE);
        g_interface_count = find_wan_interface();
        
        if (g_interface_count == 0) {
            printf("WAN interface '%s' not found. Use -i to specify interface or -l to list\n", WAN_INTERFACE);
            return -1;
        }
        
    } else {
        /* Single interface mode */
        g_interface_count = 1;
        strncpy(g_interfaces[0].name, config.interface, sizeof(g_interfaces[0].name) - 1);
        g_interfaces[0].name[sizeof(g_interfaces[0].name) - 1] = '\0';
        g_interfaces[0].active = 0;
    }
    
    printf("Filter: %s\n", config.filter);
    printf("\n");
    
    /* Initialize application monitor (always enabled) */
    if (app_monitor_init(&g_app_monitor) != 0) {
        printf("Error: Failed to initialize application monitor\n");
        return -1;
    }
    
    /* Initialize libev for periodic reporting */
    g_ev_loop = ev_loop_new(EVFLAG_AUTO);
    if (g_ev_loop) {
        ev_timer_init(&g_report_timer, periodic_report_callback, g_report_interval, g_report_interval);
        ev_timer_start(g_ev_loop, &g_report_timer);
        
        /* Start event loop in a separate thread */
        pthread_t ev_thread;
        if (pthread_create(&ev_thread, NULL, (void *(*)(void *))ev_run, g_ev_loop) != 0) {
            printf("Warning: Failed to start periodic report timer\n");
            ev_loop_destroy(g_ev_loop);
            g_ev_loop = NULL;
        } else {
            pthread_detach(ev_thread);
        }
    }
    
    /* Setup packet capture for each interface */
    int active_count = 0;
    for (int i = 0; i < g_interface_count; i++) {
        g_interfaces[i].config = config;
        g_interfaces[i].config.interface = g_interfaces[i].name;
        
        if (setup_packet_capture(&g_interfaces[i]) == 0) {
            active_count++;
        } else {
            printf("Failed to setup packet capture on %s\n", g_interfaces[i].name);
        }
    }
    
    if (active_count == 0) {
        printf("Failed to setup packet capture on any interface\n");
        return -1;
    }
    
    printf("Starting traffic capture on %d interface(s)...\n", active_count);
    printf("Application usage monitoring enabled\n");
    printf("Top 10 applications will be displayed every %d seconds\n", g_report_interval);
    printf("Press Ctrl+C to stop\n\n");
    
    /* Start capture threads for each interface */
    for (int i = 0; i < g_interface_count; i++) {
        if (g_interfaces[i].pcap_handle) {
            ret = pthread_create(&g_interfaces[i].thread_id, NULL, capture_thread, &g_interfaces[i]);
            if (ret != 0) {
                printf("Failed to create thread for %s\n", g_interfaces[i].name);
                pcap_close(g_interfaces[i].pcap_handle);
                g_interfaces[i].pcap_handle = NULL;
            }
        }
    }
    
    /* Wait for all threads to complete */
    for (int i = 0; i < g_interface_count; i++) {
        if (g_interfaces[i].pcap_handle) {
            pthread_join(g_interfaces[i].thread_id, NULL);
        }
    }
    
    /* Print statistics */
    printf("\n=== Statistics ===\n");
    printf("Total packets: %d\n", g_stats.total_packets);
    printf("DNS queries: %d\n", g_stats.dns_queries);
    printf("DNS responses: %d\n", g_stats.dns_responses);
    printf("Parsed packets: %d\n", g_stats.parsed_packets);
    printf("Error/Skipped packets: %d\n", g_stats.error_packets);
    printf("==================\n");
    
    /* Print top 10 applications */
    printf("\n=== Top 10 Applications by Usage ===\n");
    app_monitor_print_top10(&g_app_monitor);
    printf("=====================================\n");
    
    /* Cleanup */
    for (int i = 0; i < g_interface_count; i++) {
        if (g_interfaces[i].pcap_handle) {
            pcap_close(g_interfaces[i].pcap_handle);
            g_interfaces[i].pcap_handle = NULL;
        }
    }
    
    /* Stop and cleanup periodic timer */
    if (g_ev_loop) {
        ev_timer_stop(g_ev_loop, &g_report_timer);
        ev_break(g_ev_loop, EVBREAK_ALL);
        /* Give it a moment to stop */
        usleep(100000);
        ev_loop_destroy(g_ev_loop);
        g_ev_loop = NULL;
    }
    
    /* Cleanup application monitor */
    app_monitor_cleanup(&g_app_monitor);
    
    printf("DNS capture application exited cleanly\n");
    
    return 0;
}

