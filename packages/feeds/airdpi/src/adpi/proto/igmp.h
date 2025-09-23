#ifndef PROTO_IGMP_H
#define PROTO_IGMP_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define IGMP_TYPE_QUERY     0x11
#define IGMP_TYPE_REPORT_V1 0x12
#define IGMP_TYPE_REPORT_V2 0x16
#define IGMP_TYPE_LEAVE_V2  0x17
#define IGMP_TYPE_REPORT_V3 0x22

struct igmp_hdr
{
    uint8_t type;
    uint8_t max_resp_code;
    uint16_t csum;
    uint32_t mc_addr;
};

struct igmp_v3_query
{
    struct igmp_hdr hdr; /* Type is 0x11 */
    uint8_t resv_s_qrv; /* M2U will set the whole field to 0 */
    uint8_t qqic;
    uint16_t num_src;
};

struct igmp_v3_report_hdr {
    uint8_t     type; /* Always 0x22 */
    uint8_t     resv1;
    uint16_t    csum;
    uint16_t    resv2;
    uint16_t    ngrec;
};

/* V3 group record types [type] */
#define IGMPV3_MODE_IS_INCLUDE        1
#define IGMPV3_MODE_IS_EXCLUDE        2
#define IGMPV3_CHANGE_TO_INCLUDE      3
#define IGMPV3_CHANGE_TO_EXCLUDE      4
#define IGMPV3_ALLOW_NEW_SOURCES      5
#define IGMPV3_BLOCK_OLD_SOURCES      6

/* Report header is followed by ngrec group records */
struct igmp_v3_grec {
    u_int8_t    type;
    u_int8_t    aux_data_len;
    u_int16_t   nsrcs;
    u_int32_t   mc_addr;
};

#define IGMP_ALL_HOSTS		htonl(0xE0000001L)

#endif
