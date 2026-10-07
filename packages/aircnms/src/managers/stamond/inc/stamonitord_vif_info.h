#ifndef STAMONITORD_VIF_INFO_H
#define STAMONITORD_VIF_INFO_H

#include <stdbool.h>
#include <ev.h>

/* Initialize VIF info subsystem with libev loop */
bool stamonitord_vif_info_init(struct ev_loop *loop);

/* Cleanup VIF info subsystem */
void stamonitord_vif_info_cleanup(void);

/* Send VIF info event (evaluates changes and publishes to cgwd) */
bool stamonitord_send_vif_info(void);

/* Invalidate VIF info cache */
void stamonitord_invalidate_vif_cache(void);

#endif // STAMONITORD_VIF_INFO_H
