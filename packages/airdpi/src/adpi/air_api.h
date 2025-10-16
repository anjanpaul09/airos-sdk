#ifndef _AIR_API_H_
#define _AIR_API_H_

#include <linux/types.h>

/*
 * Public kernel header for consumers (mac80211/backports/vendors)
 */
struct airdpi_ops {
	int (*sta_add)(const u8 *macaddr, const char *ifname);
	int (*sta_del)(const u8 *macaddr, const char *ifname);
};

/* Ops registration (airdpi provider registers these at init) */
int airdpi_register_ops(const struct airdpi_ops *ops);
void airdpi_unregister_ops(const struct airdpi_ops *ops);
const struct airdpi_ops *airdpi_get_ops(void);

/* Direct helpers (airdpi implementation provides these; optional for consumers) */
int airdpi_sta_add(const u8 *macaddr, const char *ifname);
int airdpi_sta_del(const u8 *macaddr, const char *ifname);

#endif /* _AIR_API_H_ */


