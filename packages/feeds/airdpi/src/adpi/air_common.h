// air_common.h
#ifndef AIR_COMMON_H
#define AIR_COMMON_H

#include <linux/skbuff.h>  // Include the necessary header for struct sk_buff

#define PACKET_INGRESS 1
#define PACKET_EGRESS  0

#define AIRPRO_IS_BROADCAST(_a)              \
    ((_a)[0] == 0xff &&                         \
     (_a)[1] == 0xff &&                         \
     (_a)[2] == 0xff &&                         \
     (_a)[3] == 0xff &&                         \
     (_a)[4] == 0xff &&                         \
     (_a)[5] == 0xff)


typedef enum phy {
    PHY_ETH,
    PHY_WLAN,
} phy_t;

typedef enum rule_type {
    ACL_RULE_NONE  = 0,
    ACL_RULE_IP    = 1,
    ACL_RULE_MAC   = 2,
    ACL_RULE_PROTO = 3,
} rule_type_t;

typedef enum action {
    ACTION_DENY   =0,
    ACTION_PERMIT =1,
} action_t;

typedef enum flow_direction {
    DIR_NONE = 0,
    DIR_IN   = 1,
    DIR_OUT  = 2,
    DIR_ANY  = 3,
} dir_t;

typedef enum {
    AIR_ACTION_CONTINUE = 0,
    AIR_ACTION_DROP,
} air_action_t;


// Function declarations
extern int adpi_ingress_hook(struct sk_buff *skb, uint8_t ifindex);
extern int adpi_egress_from_bridge_hook(struct sk_buff *skb, uint8_t index);

#endif /* AIR_COMMON_H */


