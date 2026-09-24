#ifndef PORTAL_TEMPLATE_H_INCLUDED
#define PORTAL_TEMPLATE_H_INCLUDED

#include "portal_db.h"
#include <radio_vif.h>

int portal_template_init_defaults(void);
int portal_template_render_instance(portal_entry_t *entry,
        const struct airpro_mgr_wlan_vap_params *vif);
int portal_template_write_metadata(portal_entry_t *entry,
        const struct airpro_mgr_wlan_vap_params *vif);
int portal_template_load_metadata(const char *portal_id, portal_entry_t *entry);

#endif /* PORTAL_TEMPLATE_H_INCLUDED */
