#ifndef HOSTAPD_UTIL_H_INCLUDED
#define HOSTAPD_UTIL_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#define HOSTAPD_CONTROL_PATH_DEFAULT "/var/run"

bool hostapd_client_disconnect(const char *path, const char *interface, const char *disc_type,
                               const char *mac_str, uint8_t reason);
bool hostapd_btm_request(const char *path, const char *interface, const char *btm_req_cmd);
bool hostapd_rrm_set_neighbor(const char *path, const char *interface, const char *bssid, const char *nr);
bool hostapd_rrm_remove_neighbor(const char *path, const char *interface, const char *bssid);
bool hostapd_rrm_get_neighbors(const char *path, const char *interface, char *buf, const size_t buf_len);
bool hostapd_remove_station(const char *path, const char *interface, const char *mac_str);

bool hostapd_dpp_stop(const char *path, const char *interface, const char *command, const char *conf_num, int timeout_seconds);
bool hostapd_dpp_add(const char *path, const char *interface, const char *command, const char *value, const char *curve, int timeout_seconds);
bool hostapd_dpp_auth_init(const char *path, const char *interface, const char *configurator_conf_role, const char *configurator_conf_ssid_hex, const char *configurator_conf_psk_hex, int bi_id, int timeout_seconds);
bool hostapd_dpp_chirp_or_listen(const char *path, const char *interface, const char *command, int freq, int bi_id, int timeout_seconds);
bool hostapd_dpp_set_configurator_params(const char *path, const char *interface, const char *configurator_conf_role, const char *configurator_conf_ssid_hex, const char *configurator_conf_psk_hex, int timeout_seconds);

#endif /* HOSTAPD_UTIL_H_INCLUDED */
