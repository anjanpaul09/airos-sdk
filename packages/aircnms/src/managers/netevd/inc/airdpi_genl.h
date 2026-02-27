#ifndef NETEVD_AIRDPI_GENL_H
#define NETEVD_AIRDPI_GENL_H

#include <ev.h>

/**
 * airdpi_genl_init() - Start listening for AIRDPI Generic Netlink events.
 *
 * Resolves the AIRDPI family ID, subscribes to its multicast group, and
 * registers an ev_io watcher on @loop.  Non-fatal: if the AIRDPI kernel
 * module is not loaded the function logs an error and returns -1 without
 * crashing the daemon.
 *
 * @loop: libev event loop to attach to.
 * @return 0 on success, -1 on error.
 */
int airdpi_genl_init(struct ev_loop *loop);

/**
 * airdpi_genl_cleanup() - Stop the watcher and release all resources.
 *
 * @loop: The same ev_loop that was passed to airdpi_genl_init().
 */
void airdpi_genl_cleanup(struct ev_loop *loop);

#endif /* NETEVD_AIRDPI_GENL_H */
