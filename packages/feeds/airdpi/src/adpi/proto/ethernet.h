/* net/ethernet.h
   definitions for Ethernet 
 */

#ifndef PROTO_ETHERPROTO_H
#define PROTO_ETHERPROTO_H

#ifdef __KERNEL__
# include <linux/types.h>
# include <asm/byteorder.h>
#else
# include <stdint.h>
#endif

#define MAC_ADDR_LEN    6
#define NULL_MAC        ((const uint8_t*)"\x00\x00\x00\x00\x00\x00")
#define BCAST_MAC       ((const uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF")

#define ETHERTYPE_IPv4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_CMB   0x8941
#define ETHERTYPE_IPv6  0x86dd 

#define VLAN_HDR_LEN    4
#define VLAN_PRI_SHIFT  13
#define VLAN_CFI_SHIFT  12

struct ethernet_hdr {
    uint8_t dst[MAC_ADDR_LEN];
    uint8_t src[MAC_ADDR_LEN];
    uint16_t type;
} __attribute__ ((packed));

struct ethernet_vlan_hdr {
    uint8_t dst[MAC_ADDR_LEN];
    uint8_t src[MAC_ADDR_LEN];
    uint16_t tpid;
#ifdef __KERNEL__
#if defined(__BIG_ENDIAN_BITFIELD)
   struct {
        uint16_t pcp:3;
        uint16_t dei:1;
        uint16_t vid:12;
    } tci;
#elif defined (__LITTLE_ENDIAN_BITFIELD)
    struct {
        uint16_t vid:12;
        uint16_t dei:1;
        uint16_t pcp:3;
    } tci;
#else
#error "undefined endianess"
#endif
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
    struct {
        uint16_t vid:12;
        uint16_t dei:1;
        uint16_t pcp:3;
    } tci;
#elif __BYTE_ORDER == __BIG_ENDIAN
    struct {
        uint16_t pcp:3;
        uint16_t dei:1;
        uint16_t vid:12;
    } tci;
#else
#error "undefined endianess"
#endif
#endif
    uint16_t type;
} __attribute ((packed));

#endif /*PROTO_ETHERPROTO_H*/
