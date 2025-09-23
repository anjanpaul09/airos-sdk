#ifndef TARGET_SWITCH_H_INCLUDED
#define TARGET_SWITCH_H_INCLUDED

#include "log.h"
#include "os_random.h"

#include "os_ssdk.h"
#include "ssdk_util.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

#ifndef MAX_VLAN_ID
#define MAX_VLAN_ID 4095
#endif

bool target_switch_is_supported(void);
bool target_switch_assoc_vlan_to_iface(const char *ifname,
                                       const uint16_t vlan_id,
                                       bool tagged);
bool target_switch_disassoc_vlan_from_iface(const char *ifname,
                                            const uint16_t vlan_id);
#endif  /* TARGET_SWITCH_H_INCLUDED */
