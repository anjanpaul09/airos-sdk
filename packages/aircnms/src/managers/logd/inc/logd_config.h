#ifndef LOGD_CONFIG_H_INCLUDED
#define LOGD_CONFIG_H_INCLUDED

#include "logd.h"

bool logd_config_load(logd_config_t *cfg);
void logd_config_apply_defaults(logd_config_t *cfg);

#endif /* LOGD_CONFIG_H_INCLUDED */
