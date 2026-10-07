#ifndef NETCONF_PAYLOAD_VALIDATE_H
#define NETCONF_PAYLOAD_VALIDATE_H

#include <stdbool.h>
#include <stddef.h>
#include <jansson.h>

bool netconf_validate_config_payload(json_t *root, char *error, size_t error_len);
bool netconf_validate_config_string(const char *data, size_t len, char *error, size_t error_len);
bool netconf_validate_acl_payload(json_t *root, char *error, size_t error_len);
bool netconf_validate_rate_limit_payload(json_t *root, char *error, size_t error_len);

#endif
