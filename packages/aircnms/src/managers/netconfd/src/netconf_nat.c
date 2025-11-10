#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "netconf.h"

void add_nat_to_firewall()
{
    int rc;
    char cmd[256];

    //enable lan masq
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.@zone[0].masq='1'");
    rc = system(cmd);

    //zone name will be nat
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.znat='zone'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.znat.name='NatFirewall'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.znat.network='nat_network'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.znat.input=ACCEPT");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.znat.output=ACCEPT");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.znat.forward=REJECT");
    rc = system(cmd);
    
    //forwading name will be fnat 
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.fnat=forwarding");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.fnat.src='NatFirewall'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.fnat.dest='lan'");
    rc = system(cmd);

    //rule name will be rnatdhcp
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdhcp=rule");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdhcp.name='NatDhcp'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdhcp.proto=udp");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdhcp.src=NatFirewall");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdhcp.dest_port=67-68");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdhcp.target=ACCEPT");
    rc = system(cmd);

    //rule name will be rnatdns
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdns=rule");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdns.name='NatDns'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list firewall.rnatdns.proto=tcp");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list firewall.rnatdns.proto=udp");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdns.src=NatFirewall");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdns.dest_port=53");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.rnatdns.target=ACCEPT");
    rc = system(cmd);

    rc = system("uci commit firewall");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit firewall changes\n");
    }
    rc = system("/etc/init.d/firewall restart");
}

void add_nat_to_dhcp()
{
    int rc;
    char cmd[256];
    
    //devica name will be nvlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set dhcp.nat=dhcp");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set dhcp.nat.interface='nat_network'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set dhcp.nat.start='100'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set dhcp.nat.limit='150'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set dhcp.nat.leasetime='1h'");
    rc = system(cmd);
    
    rc = system("uci commit dhcp");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit dhcp changes\n");
    }
    rc = system("/etc/init.d/dnsmasq restart");
}
#ifdef CONFIG_PLATFORM_MTK_JEDI
void add_nat_to_network(nat_config_t *config)
{
    int rc;
    char cmd[256];
    
    //interface name will be vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network=interface");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.type='bridge'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.bridge_empty='1'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.proto='static'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.ipaddr='%s'", config->ipaddr);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.netmask='255.255.255.0'");
    rc = system(cmd);
    
    rc = system("uci commit network");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    rc = system("ifup nat_network");
}
#else
void add_nat_to_network(nat_config_t *config)
{
    int rc;
    char cmd[256];
    
    //devica name will be nvlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_dev='device'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_dev.name='br-nat'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_dev.type='bridge'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_dev.bridge_empty='1'");
    rc = system(cmd);
    
    //interface name will be vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network=interface");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.device='br-nat'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.proto='static'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.ipaddr='%s'", config->ipaddr);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.netmask='255.255.255.0'");
    rc = system(cmd);
    
    rc = system("uci commit network");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    rc = system("/etc/init.d/network restart");
}
#endif

void strip_trailing(char *str) 
{
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == ' ' || str[len - 1] == '\r')) {
        str[--len] = '\0';
    }
}

int netconf_check_nat_config(nat_config_t *config)
{
    int ret = 0;
    char cmd[256];
    char result[128];    

    //First check if there is existing Nat
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci get network.nat_network");
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        // Check if the result is empty
        if (strlen(result) == 0 || strstr(result, "Entry not found") != NULL) {
            return -1;  // nat is empty
        } 
    }

    memset(cmd, 0, sizeof(cmd));
    memset(result, 0, sizeof(result));
    sprintf(cmd, "uci get network.nat_network.ipaddr");
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        strip_trailing(result);
        // Check if the result is empty
        if ( strcmp(config->ipaddr, result) != 0) {
            ret = -1;
            //add_nat_to_network(config);
        } 
    }

    memset(cmd, 0, sizeof(cmd));
    memset(result, 0, sizeof(result));
    sprintf(cmd, "uci get firewall.znat");
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        // Check if the result is empty
        if (strlen(result) == 0 || strstr(result, "Entry not found") != NULL) {
            ret = -1;
            //add_nat_to_firewall();
        } 
    }

    memset(cmd, 0, sizeof(cmd));
    memset(result, 0, sizeof(result));
    sprintf(cmd, "uci get dhcp.nat");
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        // Check if the result is empty
        if (strlen(result) == 0 || strstr(result, "Entry not found") != NULL) {
            ret = -1;
            //add_nat_to_dhcp();
        } 
    }

    return ret;
}

int netconf_handle_nat_config(nat_config_t *config)
{
    int ret;

    ret = netconf_check_nat_config(config);
    if (ret == -1) {
        add_nat_to_network(config);
        add_nat_to_firewall();
        add_nat_to_dhcp();
        ret = system("ifup nat_network");
        //set network flag
        //set_flag(&flags, FLAG_NETWORK_CHANGE);
    }
    //ret = system("ifup nat_network");

    return 0;
}
