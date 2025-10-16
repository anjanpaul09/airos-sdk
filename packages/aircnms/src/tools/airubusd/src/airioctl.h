#ifndef RAYNETD_AIRIOCTL_H
#define RAYNETD_AIRIOCTL_H

#include <stdint.h>
#include <libubox/blobmsg.h>   // <-- gives struct blob_buf


int air_ioctl_block_domain(struct blob_buf *out, const char *domain);
int air_ioctl_unblock_domain(struct blob_buf *out, const char *domain);
int air_ioctl_set_user_rate_limit(struct blob_buf *out, const char *mac_addr, uint32_t rate, const char *direction);
int air_ioctl_set_wlan_rate_limit(struct blob_buf *out, const char *interface, uint32_t rate, const char *direction);
int air_ioctl_get_wlan_rate_limit(struct blob_buf *out, const char *ifname);
int air_ioctl_get_user_rate_limit(struct blob_buf *out, const char *mac_str);
int air_ioctl_get_all_top_domains(struct blob_buf *out);
int air_ioctl_get_all_clients(struct blob_buf *out);

#endif /* RAYNETD_AIRIOCTL_H */


