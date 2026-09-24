/*
 * stamonitord_history_event.h
 */

#ifndef STAMONITORD_HISTORY_EVENT_H
#define STAMONITORD_HISTORY_EVENT_H

#include <stdbool.h>
#include <stddef.h>
#include "stamonitord_history_internal.h"


bool history_event_publish(app_t *app);

bool stamonitord_send_client_history_event(char *json,
                                           size_t json_len,
                                           uint64_t timestamp_ms);

#endif