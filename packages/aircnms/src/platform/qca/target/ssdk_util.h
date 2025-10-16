#ifndef SSDK_UTIL_H_INCLUDED
#define SSDK_UTIL_H_INCLUDED

#include <stdint.h>

bool     ssdk_util_extract_values(char *input, uint32_t inp_len, char *output, uint32_t outp_len);
int      ssdk_util_conv_ifname_to_portnum(const char *ifname);
int      ssdk_util_cmd_process_output(const char *cmd);
bool     ssdk_create_vlan_entry(uint32_t vlan_id);
bool     ssdk_delete_vlan_entry(uint32_t vlan_id);
bool     ssdk_add_vlan_member_to_port(uint32_t port_num, uint32_t vlan_id, bool tagged);
bool     ssdk_rem_port_from_vlan_membership(uint32_t port_num, uint32_t vlan_id);
int32_t  ssdk_get_vlan_membership(uint32_t vlan_id);

#endif /* SSDK_UTIL_H_INCLUDED */
