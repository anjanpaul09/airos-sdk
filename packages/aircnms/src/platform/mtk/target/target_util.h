#define _GNU_SOURCE
#ifndef TARGET_UTIL_H_INCLUDED
#define TARGET_UTIL_H_INCLUDED

int util_wifi_get_parent(const char *vif, char *buf, int len);

bool util_wifi_is_phy_vif_match(const char *phy, const char *vif);

int util_get_vif_radio(const char *in_vif, char *phy_buf, int len);

#endif /* TARGET_UTIL_H_INCLUDED */
