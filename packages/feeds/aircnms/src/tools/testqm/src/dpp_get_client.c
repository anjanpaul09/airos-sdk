#include "sm.h"

static struct ev_timer  genmsg_timer;

void fill_random_mac(mac_address_t mac, int index)
{
    for (int i = 0; i < MAC_ADDRESS_LEN; i++)
    {
        mac[i] = (i+index) % 256;
    }
}

void fill_random_ip(ip_address_t ip, int index)
{
    //sprintf(ip, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    sprintf(ip, "%d.%d.%d.%d", 192, 168, 1, 1 + index);
}

void fill_random_hostname(hostname_t hostname, int index)
{
    sprintf(hostname, "client-%d", index);
    //sprintf(hostname, "client-%d", rand() % 1000);
}

void fill_random_essid(radio_essid_t essid, int index)
{
    sprintf(essid, "Network-%d", index);
}

void fill_random_network_id(network_id_t networkid)
{
    sprintf(networkid, "NetID-%d", rand() % 10000);
}

void dpp_dummy_get_client_record(dpp_client_record_t *record, int index)
{
    //record->info.type = rand() % 6;  // Random radio type
    record->info.type = 2;  // Random radio type
    fill_random_mac(record->info.mac, index);
    fill_random_ip(record->info.ip, index);
    fill_random_hostname(record->info.hostname, index);
    sprintf(record->info.ifname, "wlan%d", rand() % 10);
    fill_random_essid(record->info.essid, index);
    fill_random_network_id(record->info.networkid);

    record->stats.bytes_tx = rand() % 1000000;
    record->stats.bytes_rx = rand() % 1000000;
    record->stats.frames_tx = rand() % 10000;
    record->stats.frames_rx = rand() % 10000;
    record->stats.retries_rx = rand() % 100;
    record->stats.retries_tx = rand() % 100;
    record->stats.errors_rx = rand() % 10;
    record->stats.errors_tx = rand() % 10;
    record->stats.rate_rx = rand() % 1000 / 10.0;
    record->stats.rate_tx = rand() % 1000 / 10.0;
    record->stats.rssi = -rand() % 100;
    record->stats.rate_rx_perceived = rand() % 1000 / 10.0;
    record->stats.rate_tx_perceived = rand() % 1000 / 10.0;

    //record->is_connected = rand() % 2;
    record->is_connected = 1;
    //record->connected = rand() % 2;
    //record->disconnected = rand() % 2;
    //record->connect_ts = rand();
    //record->disconnect_ts = rand();
    record->duration_ms = rand() % 100000;
    //record->uapsd = rand() % 2;
}
