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
#include "dns.h"

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

/* Signal handler for graceful shutdown */
void signal_handler(int sig)
{
    (void)sig;
    printf("\nReceived signal, shutting down...\n");
    g_running = 0;
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
    
    /* Print packet summary for debugging - like reference implementation */
    if (g_verbose) {
        printf("[CAPTURE] %s: Packet captured: %u bytes\n", if_handle->name, header->caplen);
        fflush(stdout);
    }
    
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
            printf("%s: [DNS-QUERY] %s:%d -> %s:%d | Domain: %s | ID: 0x%04x\n",
                   if_handle->name,
                   app_data.src_ip, app_data.src_port,
                   app_data.dst_ip, app_data.dst_port,
                   app_data.domain[0] ? app_data.domain : "unknown",
                   app_data.dns_id);
        } else {
            g_stats.dns_responses++;
            const char *rcode_str = dns_rcode_to_string(app_data.dns_rcode);
            
            printf("%s: [DNS-RESP]  %s:%d -> %s:%d | RCODE: %s | ID: 0x%04x\n",
                   if_handle->name,
                   app_data.src_ip, app_data.src_port,
                   app_data.dst_ip, app_data.dst_port,
                   rcode_str, app_data.dns_id);
        }
        fflush(stdout);
        
        if (g_verbose) {
            printf("  Timestamp: %lld, Packet size: %u bytes\n", 
                   (long long)app_data.timestamp, header->caplen);
        }
    } else {
        g_stats.error_packets++;
        if (g_verbose) {
            printf("[SKIP] Non-DNS packet: %u bytes\n", header->caplen);
        }
    }
}

void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("DNS Traffic Capture - Extract app and website details from network interface\n\n");
    printf("Options:\n");
    printf("  -i, --interface IF   Interface to capture on (default: any)\n");
    printf("  -f, --filter FILTER  BPF filter (default: \"udp port 53\")\n");
    printf("  -s, --snaplen SIZE   Snapshot length (default: 1500)\n");
    printf("  -t, --timeout MS     Read timeout in ms (default: 100)\n");
    printf("  -P, --promiscuous    Enable promiscuous mode\n");
    printf("  -v, --verbose        Enable verbose output\n");
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
    printf("  - Track application usage patterns\n");
    printf("  - Generate reports and statistics\n");
    printf("  - Support filtering and aggregation\n");
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
        .filter = "udp port 53",
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
        {"help",        no_argument,       0, 'h'},
        {"list",        no_argument,       0, 'l'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "i:f:s:t:Pvhl", long_options, NULL)) != -1) {
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
    
    /* If no interface specified, find all phy interfaces */
    if (config.interface == NULL) {
        printf("Auto-detecting WiFi interfaces (phy*)\n");
        g_interface_count = find_phy_interfaces();
        
        if (g_interface_count == 0) {
            printf("No phy* interfaces found. Use -i to specify interface or -l to list\n");
            return -1;
        }
        
        printf("Found %d WiFi interface(s):\n", g_interface_count);
        for (int i = 0; i < g_interface_count; i++) {
            printf("  - %s\n", g_interfaces[i].name);
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
    
    printf("Starting DNS traffic capture on %d interface(s)...\n", active_count);
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
    
    /* Cleanup */
    for (int i = 0; i < g_interface_count; i++) {
        if (g_interfaces[i].pcap_handle) {
            pcap_close(g_interfaces[i].pcap_handle);
            g_interfaces[i].pcap_handle = NULL;
        }
    }
    
    printf("DNS capture application exited cleanly\n");
    
    return 0;
}

