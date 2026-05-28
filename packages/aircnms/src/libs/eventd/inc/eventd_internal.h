#ifndef EVENTD_INTERNAL_H
#define EVENTD_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

bool eventd_mqtt_publish(size_t mlen, const void *mbuf);
bool eventd_ubus_is_ready(void);

#endif /* EVENTD_INTERNAL_H */
