#include "onbd.h"
#include <assert.h>
#include <string.h>

onbd_state_t g_onbd_state;

int main(void)
{
    onbd_state_t s = {0};
    assert(!onbd_valid_device_id(NULL));
    assert(!onbd_valid_device_id("XXXXXXXXXX"));
    assert(!onbd_valid_device_id("123"));
    assert(!onbd_valid_device_id("123456789A"));
    assert(onbd_valid_device_id("8005356393"));

    s.ubus_available = true;
    s.network_available = true;
    s.cgwd_available = true;
    s.stored_identity_valid = true;
    s.legacy_online = true;
    s.carrier_available = true;
    s.management_ip_available = true;
    s.default_route_available = true;
    s.gateway_reachable = true;
    s.dns_available = true;
    s.dns_resolved = true;
    s.internet_available = true;
    s.cloud_available = true;
    onbd_derive_shadow_state(&s);
    assert(s.lifecycle == ONBD_LIFECYCLE_ENROLLED);
    assert(s.connectivity == ONBD_CONN_ONLINE);
    assert(!strcmp(onbd_visible_state(&s), "ENROLLED"));

    s.configuration = ONBD_CONFIG_APPLIED;
    s.applied_revision = 7;
    onbd_derive_shadow_state(&s);
    assert(s.lifecycle == ONBD_LIFECYCLE_OPERATIONAL);
    assert(s.operational_once);
    assert(!strcmp(onbd_visible_state(&s), "OPERATIONAL"));

    memset(&s, 0, sizeof(s));
    s.operational_once = true;
    s.ubus_available = true;
    s.network_available = true;
    s.cgwd_available = true;
    onbd_derive_shadow_state(&s);
    assert(s.lifecycle == ONBD_LIFECYCLE_OPERATIONAL);
    assert(!strcmp(onbd_visible_state(&s), "OPERATIONAL"));
    assert(!s.fallback_active);

    memset(&s, 0, sizeof(s));
    s.ubus_available = true;
    s.network_available = true;
    s.carrier_available = true;
    s.recovery_ssid_enabled = true;
    s.dhcp_wait_ticks = 6;
    s.dhcp_retry_count = 3;
    onbd_derive_shadow_state(&s);
    onbd_derive_shadow_state(&s);
    onbd_derive_shadow_state(&s);
    assert(s.connectivity == ONBD_CONN_DHCP_FAILED);
    assert(!strcmp(s.reason_code, "DHCP_TIMEOUT"));
    assert(s.fallback_active);
    assert(s.lifecycle == ONBD_LIFECYCLE_RECOVERY);

    memset(&s, 0, sizeof(s));
    s.ubus_available = true;
    s.network_available = true;
    s.carrier_available = true;
    s.management_ip_available = true;
    s.default_route_available = true;
    s.gateway_reachable = true;
    s.dns_available = true;
    s.dns_resolved = false;
    onbd_derive_shadow_state(&s);
    assert(s.connectivity == ONBD_CONN_DNS_FAILED);
    assert(!strcmp(s.reason_code, "DNS_RESOLUTION_FAILED"));

    s.dns_resolved = true;
    s.internet_available = true;
    s.cloud_available = false;
    onbd_derive_shadow_state(&s);
    assert(s.connectivity == ONBD_CONN_CLOUD_UNREACHABLE);
    assert(!strcmp(s.reason_code, "CLOUD_HTTPS_FAILED"));
    return 0;
}
