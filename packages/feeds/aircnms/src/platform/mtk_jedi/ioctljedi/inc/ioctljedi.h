#ifndef IOCTLJEDI_H
#define IOCTLJEDI_H

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdint.h>  
#include <ev.h>
#include <linux/wireless.h>

#include "dpp_types.h"

#define IOCTLJEDI_IFNAME_LEN       17
#define IOCTLJEDI_IFNAME_QTY       16
#define IOCTLJEDI_IFNAME_ARG       0
#define IOCTLJEDI_IFNAME_ARG_QTY   1

typedef struct
{
    ifname_t                            ifname;
    mac_address_t                       mac;
    radio_essid_t                       essid;
    radio_type_t                        radio_type;
    bool                                sta;
} ioctljedi_interface_t;

typedef struct
{
    ioctljedi_interface_t              phy[IOCTLJEDI_IFNAME_QTY];
    uint32_t                            qty;
} ioctljedi_interfaces_t;

typedef enum
{
    IOCTL_STATUS_ERROR        = -1,
    IOCTL_STATUS_OK           = 0,
    IOCTL_STATUS_NOSUPPORT    = 1
} ioctl_status_t;

ioctl_status_t ioctljedi_init(struct ev_loop *loop, bool init_callback);
ioctl_status_t ioctljedi_close(struct ev_loop *loop);
int            ioctljedi_fd_get(void);


ioctl_status_t ioctljedi_interfaces_get(
        int                     sock_fd,
        char                   *ifname,
        char                   *args[],
        int                     radio_type);

ioctl_status_t ioctljedi_get_essid(
        int                     sock_fd,
        const char             *ifname,
        char                   *dest,
        int                     dest_len);

typedef int (*ioctljedi_interfaces_find_cb)(
        int                     skfd,
        char                   *ifname,
        char                   *args[],
        int                     count);

void ioctljedi_interfaces_find(
        int                     sock_fd,
        ioctljedi_interfaces_find_cb         fn,
        char                   *args[],
        radio_type_t            type);

int ioctljedi_request_send(
        int                     sock_fd,
        const char             *ifname,
        int                     command,
        struct iwreq           *request);

#endif  // IOCTLJEDI_H
