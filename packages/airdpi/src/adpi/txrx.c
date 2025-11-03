#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/timer.h>
#include <linux/string.h> // For strcmp
#include "dhcp.h"
#include "air_coplane.h"
#include "air_coplane.h"
#include "air_ioctl.h"
#include "proto/ipv4.h"
#include "proto/udp.h"
#include "proto/tcp.h"
#include "proto/dhcp.h"
#include "proto/ethernet.h"
#include <linux/timekeeping.h>  
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#define MAX_IP_ADDR_LEN     16

#define UDP_PORT_BOOTPS     67
#define UDP_PORT_BOOTPC     68
#define UDP_PORT_DNS        53
#define UDP_PORT_MDNS       5353

//#define MAX_STA_HOSTNAME    32
#define MAC_ADDR_LEN        6

/* air_vif removed: using coplane */

//static unsigned long rx_total_len = 0;
//static unsigned long tx_total_len = 0;

//extern struct timer_list my_timer; // Timer for resetting the counter
//static unsigned int tx_packet_counter = 0;
////static unsigned int rx_packet_counter = 0;

extern struct airpro_coplane *coplane;
extern struct ratelimit_bucket *wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];
extern struct ratelimit_bucket *user_wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];
int rl_drop_packet(struct wlan_sta *se, const size_t len, unsigned int dir);
int sta_rc_table_lookup(struct wlan_sta *se, uint8_t *macaddr, unsigned int dir, uint8_t ifindex);
struct wlan_sta *sta_table_lookup(uint8_t *macaddr, int dir, uint8_t ifindex);

int snoop_dns_response(struct sk_buff *skb, unsigned int ofs);

// DNS header structure for parsing
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

int is_blocked_ip(struct airpro_coplane *cp, __be32 ip) {
    struct blocked_domain *bd;
    struct blocked_ip *bi;
    int bkt;

    hash_for_each(cp->blocked_domains, bkt, bd, node) {
        if (!bd->active)
            continue;
        hlist_for_each_entry(bi, &bd->ip_list, node) {
            if (bi->ip == ip)
                return 1;
        }
    }
    return 0;
}

// Parse DNS response to extract domain-to-IP mappings
static int parse_dns_response(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + (iph->ihl << 2));
    struct dns_header *dns = (struct dns_header *)((uint8_t *)udph + sizeof(*udph));
    unsigned char *data = (unsigned char *)(dns + 1);
    unsigned int len = skb->len - ((uint8_t *)data - skb->data);
    unsigned char domain[MAX_DOMAIN_NAME_LEN] = {0};
    unsigned char *ptr = data;
    int qdcount = ntohs(dns->qdcount);
    int ancount = ntohs(dns->ancount);
    int i, j, pos = 0;

    if (len < sizeof(*dns)) return 0;

    // Skip questions
    for (i = 0; i < qdcount && ptr < skb->data + skb->len; i++) {
        while (*ptr && ptr < skb->data + skb->len) {
            int len = *ptr++;
            if (len == 0xc0) { // Pointer
                ptr++;
                break;
            }
            ptr += len;
        }
        ptr += 4; // QTYPE, QCLASS
    }

    // Parse answers
    for (i = 0; i < ancount && ptr < skb->data + skb->len; i++) {
        pos = 0;
        // Extract domain name
        while (*ptr && pos < MAX_DOMAIN_NAME_LEN - 1 && ptr < skb->data + skb->len) {
            int len = *ptr++;
            if (len == 0xc0) { // Pointer
                ptr++;
                break;
            }
            if (pos > 0) domain[pos++] = '.';
            for (j = 0; j < len && pos < MAX_DOMAIN_NAME_LEN - 1; j++) {
                domain[pos++] = *ptr++;
            }
        }
        domain[pos] = '\0';

        // Skip TYPE, CLASS, TTL
        ptr += 8;
        if (ptr + 4 > skb->data + skb->len) break;

        // Check for A record
        if (ntohs(*(uint16_t *)(ptr - 8)) == 1) {
            __be32 ip = *(__be32 *)ptr;
            ptr += 4;

            // Check if domain is blocked
            struct blocked_domain *bd;
            unsigned long flags;
            spin_lock_irqsave(&coplane->domain_lock, flags);
            hash_for_each_possible(coplane->blocked_domains, bd, node, hash_string(domain)) {
                if (bd->active && strcmp(bd->domain, domain) == 0) {
                    struct blocked_ip *bi = kmalloc(sizeof(*bi), GFP_ATOMIC);
                    if (bi) {
                        bi->ip = ip;
                        hlist_add_head(&bi->node, &bd->ip_list);
                        printk(KERN_INFO "Blocked IP %pI4 for domain %s\n", &ip, domain);
                    }
                    break;
                }
            }
            spin_unlock_irqrestore(&coplane->domain_lock, flags);
        }
    }
    return 0;
}

struct client_node *client_reg_table_lookup(uint8_t *macaddr)
{

    struct client_node *cn;
    int hash;

    if (macaddr) {
        hash = CLIENT_HASH(macaddr);
        OS_SPIN_LOCK(&coplane->reg.lock);
        LIST_FOREACH(cn, &coplane->reg.client_hash[hash], nh) {
            if (IEEE80211_ADDR_EQ(cn->macaddr, macaddr)) {
                OS_SPIN_UNLOCK(&coplane->reg.lock);
                return cn;
            }
        }
        OS_SPIN_UNLOCK(&coplane->reg.lock);
    }
    return NULL;
}

void get_ip_str(u32 *sip, u8 *ipstr)
{
    snprintf(ipstr, MAX_IP_ADDR_LEN, "%pI4", sip);
}

struct client_node *client_reg_table_alloc(char *macaddr)
{
    struct client_node *cn;
    int hash = 0;

    if (!(cn = kmalloc(sizeof(*cn), GFP_ATOMIC))){
        printk("Unable to allocate discovered sta entry\n");
        return NULL;
    }
    memset(cn, 0, sizeof(struct client_node));
    IEEE80211_ADDR_COPY(cn->macaddr, macaddr);
    cn->connected_tms = ktime_get_real_seconds(); // Store connection timestamp
    hash = CLIENT_HASH(macaddr);
    
    OS_SPIN_LOCK(&coplane->reg.lock);
    LIST_INSERT_HEAD(&coplane->reg.client_hash[hash], cn, nh);
    TAILQ_INSERT_TAIL(&coplane->reg.client_list, cn, nl);
    OS_SPIN_UNLOCK(&coplane->reg.lock);
    
    return cn;
}

static unsigned int parse_layer2_header(struct sk_buff *skb, unsigned int *proto, unsigned int *vlan)
{
    const struct ethernet_hdr * const eh = (const struct ethernet_hdr *)skb->data;

    if (htons(eh->type) >= 1536) {
        if (eh->type == htons(ETHERTYPE_VLAN)) {
            const struct ethernet_vlan_hdr * const evh = (const struct ethernet_vlan_hdr *)skb_mac_header(skb);
            if (skb->len < sizeof(struct ethernet_vlan_hdr)) {
                //printk("runt VLAN packet\n");
                return 0;
            }
            *proto = (evh->type);
            *vlan = ntohs(evh->tci.vid);
            return sizeof(struct ethernet_vlan_hdr);
        } else {
            if (skb->vlan_tci)
                *vlan = skb->vlan_tci & VLAN_VID_MASK;
            else
                *vlan = 1; /* Default assignment */
            *proto = (eh->type);
            return sizeof(struct ethernet_hdr);
        }
    } else {
        return 0;
    }
}

static int air_parse_dhcp(struct sk_buff *skb, unsigned int ofs, struct iphdr *iph)
{
    struct dhcp_hdr *dhcp = (struct dhcp_hdr *)(skb->data + ofs);
    struct client_node *cn = NULL;
    uint8_t *ptr, *end;
    size_t len;
    u32 tid;
    u8 dora_state;
    u32 req_ip;
    u32 rel_ip;

    if (memcmp(dhcp->magic, DHCP_MAGIC_COOKIE, sizeof(dhcp->magic))) {
        return -1;
    }

    cn = client_reg_table_lookup(dhcp->chaddr);
    if (!cn) {
        cn = client_reg_table_alloc(dhcp->chaddr);
        if (cn) {
            cn->connected_tms = ktime_get_real_seconds(); // Store connection timestamp
        }
    }
    tid = ntohl(dhcp->tid);

    ptr = (char *)(dhcp + 1);
    end = skb->data + skb->len;
     while (ptr < end) {
        unsigned int option, oplen;
        option = *ptr;
        ptr++;
        if (option == DHCP_OPTION_PAD || option == DHCP_OPTION_END)
            continue;
        if (ptr >= end)
            return -1;

        oplen = *ptr;
        if (++ptr + oplen > end)
            return -1;
    if (option == DHCP_OPTION_HOSTNAME) {
            int hlen = (oplen >= MAX_STA_HOSTNAME) ? (MAX_STA_HOSTNAME-1) : oplen;
            if (cn) {
                memset(cn->hostname, 0, sizeof(cn->hostname));
                memcpy(cn->hostname, ptr, hlen);
            }
        } else if ((option == DHCP_OPTION_REQ_PARAM) && oplen) {
            int i;
            if (cn) {
                memset(cn->fingerprint, 0, sizeof(cn->fingerprint));
                for (i = 0; (i < oplen && i < 100); i++) { // #params has to be well under 100, saves us from overruns of the strcat too
                    char s[5];
                    snprintf(s, sizeof(s), "%d,", ptr[i]);
                    strcat(cn->fingerprint, s);
                }
            }
        } else if (option == DHCP_OPTION_REQUESTED_IP && oplen == 4) {
            memcpy(&req_ip, ptr, 4);
            if (cn) {
                 cn->ip = req_ip;
            }
        } else if (option == DHCP_OPTION_RELEASED_IP && oplen == 4) {
            memcpy(&rel_ip, ptr, 4);
            if (cn) {
                cn->ip = rel_ip;
            }
        } else if (option == DHCP_OPTION_MSG_TYPE && oplen == 1) {
            u32 msgtype = *ptr;
            switch (msgtype) {
                case DHCP_MSG_TYPE_DISCOVER: {
                    dora_state = DHCP_MSG_TYPE_DISCOVER;
                } break;
                case DHCP_MSG_TYPE_OFFER: {
                    dora_state = DHCP_MSG_TYPE_OFFER;
                } break;
                case DHCP_MSG_TYPE_REQUEST: {
                    dora_state = DHCP_MSG_TYPE_REQUEST;
                } break;
                case DHCP_MSG_TYPE_ACK: {
                    dora_state = DHCP_MSG_TYPE_ACK;
                } break;
                default: {
                } break;
            }
        //printk("Anjan: dorastate=%d\n", dora_state);
        } else if (option == DHCP_OPTION_LEASE_TIME && oplen == 4) {
            if (cn) {
                u32 lease_time;
                memcpy(&lease_time, ptr, sizeof(lease_time));
                cn->lease_time = ntohl(lease_time);
            }
        }
        ptr += oplen;
    }
    len = skb_tail_pointer(skb) - skb->data;
    if (skb->dev) {
        if (cn) {
            memset(cn->ifname, 0, sizeof(cn->ifname));
            strlcpy(cn->ifname, skb->dev->name, sizeof(cn->ifname));
        }
    }

    return 0;
}

struct wlan_sta *sta_table_lookup(uint8_t *macaddr, int dir, uint8_t ifindex)
{
    struct wlan_sta *sta = NULL;
    uint8_t sta_found = 0;
    int hash;

    hash = WLAN_STA_HASH(macaddr);
    LIST_FOREACH(sta, &coplane->wlan_client.wlan_coplane_sta_hash[hash], ws_hash) {
        if (IEEE80211_ADDR_EQ(sta->src_mac, macaddr)) {
            sta_found = 1;
            return sta;
        }
    }

    if (!sta_found) {
        struct wlan_sta *sta_new = NULL;
        sta_new = kmalloc(sizeof(struct wlan_sta), GFP_KERNEL);
        if (!sta_new) {
            return NULL;
        }

        memset(sta_new, 0, sizeof(struct wlan_sta));
        IEEE80211_ADDR_COPY(sta_new->src_mac, macaddr);
        sta_new->domain_name_count = 0;
        sta_new->wlan_id = ifindex;
        if (user_wlan_rl[ifindex][AIR_RL_DIR_UPLINK]) {
            sta_new->rl[AIR_RL_DIR_UPLINK] = user_wlan_rl[ifindex][AIR_RL_DIR_UPLINK];
        }
        if (user_wlan_rl[ifindex][AIR_RL_DIR_DOWNLINK]) {
            sta_new->rl[AIR_RL_DIR_DOWNLINK] = user_wlan_rl[ifindex][AIR_RL_DIR_DOWNLINK];
        }
      
        printk("AIRDPI: adding client to queue: MAC=%02x:%02x:%02x:%02x:%02x:%02x hash=%d wlan-id=%d\n",
               sta_new->src_mac[0], sta_new->src_mac[1], sta_new->src_mac[2],
               sta_new->src_mac[3], sta_new->src_mac[4], sta_new->src_mac[5],
               hash, sta_new->wlan_id);

        OS_SPIN_WLAN_STA_LOCK(&coplane->wlan_client.wlan_client_lock);

        TAILQ_INSERT_TAIL(&coplane->wlan_client.wlan_coplane_sta_list, sta_new, ws_next);
        LIST_INSERT_HEAD(&coplane->wlan_client.wlan_coplane_sta_hash[hash], sta_new, ws_hash);
        OS_SPIN_WLAN_STA_UNLOCK(&coplane->wlan_client.wlan_client_lock);
        
        printk("AIRDPI: client added to queue successfully: MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
               sta_new->src_mac[0], sta_new->src_mac[1], sta_new->src_mac[2],
               sta_new->src_mac[3], sta_new->src_mac[4], sta_new->src_mac[5]);
        
        return sta_new;
    }

    return NULL;
}

static int update_client_quota(struct sk_buff *skb, struct client_node *cn, int dir)
{
    struct timespec64 ts;
    size_t len;

    ktime_get_real_ts64(&ts);  // Gets current real time in seconds + nanoseconds

    cn->ts = ((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000));  // Convert to milliseconds
    len = skb_tail_pointer(skb) - skb->data;
    // update client counters
    if (dir == PACKET_INGRESS) {
        cn->rxbytes += len;
    } else {
        cn->txbytes += len;
    }
    
    return 0;
}

unsigned int air_ingress_hook(struct sk_buff *skb, const struct nf_hook_state* state)
{
    unsigned int offset, type, vlan;
    struct client_node *cn = NULL;
    struct wlan_sta *se = NULL;
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    int ip_hdr_len = iph->ihl << 2;
    int vap_id;
    uint8_t macaddr[ETH_ALEN] = {0};
    size_t len;

    memcpy(macaddr, eth->h_source, ETH_ALEN); 

    if (skb->dev && (strncmp(skb->dev->name, "wan", 3) == 0 ||
                    strncmp(skb->dev->name, "mesh", 4) == 0)) {
        return NF_ACCEPT;
    }

    offset = parse_layer2_header(skb, &type, &vlan);
    if (offset) {
        cn = client_reg_table_lookup(macaddr);
        if (!cn) {
            return NF_ACCEPT;
        }

        update_client_quota(skb, cn, PACKET_INGRESS);

        vap_id = IFNAME_HASH(skb->dev->name);
        se = sta_table_lookup(macaddr, PACKET_INGRESS, vap_id);
        if (!se) {
            return NF_ACCEPT;
        }

        //len = skb_tail_pointer(skb) - skb_mac_header(skb);
        len = skb->len;
        if (rl_drop_packet(se, len, AIR_RL_DIR_UPLINK)) {
            return NF_DROP;
        }
    }

    // Keep linearize only if later code *needs* direct access
    // But current parsing uses ip_hdr, which should be safe already
    // If DHCP parse needs linear buffer, do it inside that function
    // skb_linearize(skb);

    if (cn) {
        if (!cn->ip) {
            enum ip_conntrack_info ctinfo;
            struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
            if (ct && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED)) {
                cn->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
            } else {
                cn->ip = iph->saddr;
            }
        }

        if (cn->ifname[0] == '\0') {
            strncpy(cn->ifname, skb->dev->name, sizeof(cn->ifname) - 1);
            cn->ifname[sizeof(cn->ifname) - 1] = '\0';
        }
    }

    if (iph->protocol == IPPROTO_TCP) {
        // Placeholder if needed later
        // struct tcphdr *tcph = (struct tcphdr *)(((uint8_t *)iph) + ip_hdr_len);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)((uint8_t *)iph + ip_hdr_len);

        if (udph->dest == htons(UDP_PORT_DNS)) {
            // DNS processing (if needed)
        } else if ((udph->dest == htons(UDP_PORT_BOOTPC) && udph->source == htons(UDP_PORT_BOOTPS)) ||
                   (udph->source == htons(UDP_PORT_BOOTPC) && udph->dest == htons(UDP_PORT_BOOTPS))) {
            int ofs = ip_hdr_len + sizeof(struct udphdr);
            if (skb->len < ofs + sizeof(struct dhcp_hdr)) {
                return NF_ACCEPT;
            }  
            air_parse_dhcp(skb, ofs, iph);
        }
    }

    return NF_ACCEPT;
}


unsigned int air_egress_hook(struct sk_buff *skb, const struct nf_hook_state* state)
{
    unsigned int offset, type, vlan;
    struct client_node *cn = NULL;
    struct wlan_sta *se = NULL;
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    int ip_hdr_len = iph->ihl << 2;
    uint8_t macaddr[ETH_ALEN];
    int vap_id;
    size_t len;
    u8 sipstr[16];

    memcpy(macaddr, eth->h_dest, ETH_ALEN); // memset removed as memcpy overwrites all bytes
    
    if (skb->dev && (strncmp(skb->dev->name, "wan", 3) == 0 ||
                    strncmp(skb->dev->name, "mesh", 4) == 0)) {
        return NF_ACCEPT;
    }
    
    offset = parse_layer2_header(skb, &type, &vlan);
    if (offset) {
        cn = client_reg_table_lookup(macaddr);
        if (!cn) {
            return NF_ACCEPT;
        }

        update_client_quota(skb, cn, PACKET_EGRESS);

        vap_id = IFNAME_HASH(skb->dev->name);
        se = sta_table_lookup(macaddr, PACKET_EGRESS, vap_id);
        if (!se) {
            return NF_ACCEPT;
        }

        //len = skb_tail_pointer(skb) - skb_mac_header(skb);
        len = skb->len;
        if (rl_drop_packet(se, len, AIR_RL_DIR_DOWNLINK)) {
            return NF_DROP;
        }
    }

    get_ip_str(&iph->saddr, sipstr); // memset not needed; get_ip_str should handle buffer safety

    if (iph->protocol == IPPROTO_TCP) {
        // Currently empty, placeholder for future logic
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)((uint8_t *)iph + ip_hdr_len);

        if (udph->dest == htons(UDP_PORT_DNS)) {
            // DNS request – currently no processing
        } else if (udph->source == htons(UDP_PORT_DNS)) {
            snoop_dns_response(skb, sizeof(struct tcphdr) + sizeof(struct udphdr));
            parse_dns_response(skb);
        }
    }

    return NF_ACCEPT;
}

