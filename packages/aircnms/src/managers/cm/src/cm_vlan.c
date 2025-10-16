#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "cm.h"

int execute_uci_command(const char *command, char *result, size_t result_size) 
{
    printf("Executing command: %s\n", command);
    FILE *fp;
    char buffer[128];

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return -1;
    }

    result[0] = '\0'; // Ensure the result is empty initially
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncat(result, buffer, result_size - strlen(result) - 1);
    }

    pclose(fp);
    return 0;
}


void add_vlan_to_firewall(int vlan)
{
    int rc;
    char cmd[256];
   
    //zone name will be vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.zone%d=zone", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.zone%d.name='%d'", vlan, vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list firewall.zone%d.network='%d'", vlan, vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.zone%d.input=ACCEPT", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.zone%d.output=ACCEPT", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.zone%d.forward=ACCEPT", vlan);
    rc = system(cmd);
    
    //forwading name will be fvlan 
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.f%d=forwarding", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.f%d.src='%d'", vlan, vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set firewall.f%d.dest='wan'", vlan);
    rc = system(cmd);

    rc = system("uci commit firewall");
    rc = system("/etc/init.d/firewall restart");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit firewall changes\n");
    }
    return;
}


void del_vlan_frm_firewall(int vlan)
{
    int rc;
    char cmd[256];
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci delete firewall.zone%d", vlan);
    rc = system(cmd);
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci delete firewall.f%d", vlan);
    rc = system(cmd);

    rc = system("uci commit firewall");
    rc = system("/etc/init.d/firewall restart");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit firewall changes\n");
    }
    return;
}

#ifdef CONFIG_PLATFORM_MTK_JEDI
void del_vlan_frm_network(int vlan)
{
    int rc;
    char cmd[256];
    
    //deleting interface vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci delete network.%d", vlan);
    rc = system(cmd);

    rc = system("uci commit network");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    return;
}
#else
void del_vlan_frm_network(int vlan)
{
    int rc;
    char cmd[256];
    
    //deleting device nvlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci delete network.n%d", vlan);
    rc = system(cmd);
    
    //deleting interface vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci delete network.%d", vlan);
    rc = system(cmd);

    rc = system(cmd);
    rc = system("uci commit network");
    rc = system("/etc/init.d/network restart");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    return;
}
#endif

#ifdef CONFIG_PLATFORM_MTK_JEDI
void add_vlan_to_network(int vlan, char *section_name)
{
    int rc;
    char cmd[256];

    //interface name will be vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.%d=interface", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.%d.type='bridge'", vlan);
    rc = system(cmd);
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.%d.proto='none'", vlan);
    rc = system(cmd);
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list network.%d.ifname=eth0.%d", vlan, vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list network.%d.ifname=%s", vlan, section_name);
    rc = system(cmd);

    rc = system("uci commit network");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    return;
}
#else
void add_vlan_to_network(int vlan, char *section_name)
{
    int rc;
    char cmd[256];
    
    //devica name will be nvlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.n%d=device", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.n%d.name='br-%d'", vlan, vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.n%d.type='bridge'", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list network.n%d.ports='wan.%d'", vlan, vlan);
    rc = system(cmd);

    //interface name will be vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.%d=interface", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.%d.device='br-%d'", vlan, vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.%d.proto='none'", vlan);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci add_list network.%d.wiface='%s'", vlan, section_name);
    rc = system(cmd);

    rc = system("uci commit network");
    rc = system("/etc/init.d/network restart");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    return;
}
#endif

#ifdef CONFIG_PLATFORM_MTK_JEDI
void set_vlan_network(int vlan, const char* section_name)
{
    int rc;
    char cmd[256];
    char result[128];

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci get network.%d", vlan);
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        if (strstr(result, "interface") != NULL) {
            sprintf(cmd, "uci get network.%d.ifname", vlan);
            if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
                if ( strstr(result, section_name) != NULL ) {
                    return;
                } else {
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci add_list network.%d.ifname=%s", vlan, section_name);
                    rc = system(cmd);
                    rc = system("uci commit network");
                    //set network flag
                    //set_flag(&flags, FLAG_NETWORK_CHANGE);
                    memset(cmd, 0, sizeof(cmd));
                    snprintf(cmd, sizeof(cmd), "ifup %d", vlan);
                    system(cmd);
                    if (rc != 0) {
                        fprintf(stderr, "Failed to commit Network changes\n");
                    }
                    return;
                }
            }
        } else {
        // if vlan network not exist
        // add new vlan network
        add_vlan_to_network(vlan, (char *)section_name);
        add_vlan_to_firewall(vlan);
        //set network flag
        //set_flag(&flags, FLAG_NETWORK_CHANGE);
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "ifup %d", vlan);
        system(cmd);
        }
    }
}
#else
void set_vlan_network(int vlan, char* section_name)
{
    int rc;
    char cmd[256];
    char result[128];    

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci get network.%d", vlan);
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        if (strstr(result, "interface") != NULL) {
            sprintf(cmd, "uci get network.%d.wiface", vlan);
            if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
                if ( strstr(result, section_name) != NULL ) {
                    return;
                } else {
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci add_list network.%d.wiface='%s'", vlan, section_name);
                    rc = system(cmd);
                    rc = system("uci commit network");
                    if (rc != 0) {
                        fprintf(stderr, "Failed to commit Network changes\n");
                    }
                    return;
                }
            }
        } else {
        // if vlan network not exist
        // add new vlan network
        add_vlan_to_network(vlan, (char *)section_name);
        add_vlan_to_firewall(vlan);
        //set network flag
        set_flag(&flags, FLAG_NETWORK_CHANGE);
        }
    }
}
#endif

#ifdef CONFIG_PLATFORM_MTK_JEDI
void del_wiface_frm_vlan_network(int vlan, char *section_name)
{
    int rc;
    char cmd[256];
    char result[128];    
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del_list network.%d.ifname=%s", vlan, section_name);
    rc = system(cmd);
    rc = system("uci commit network");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    
    /*check if the wiface list is empty
      if empty delete the vlan network 
      and firewall */
    sprintf(cmd, "uci get network.%d.ifname", vlan);
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        result[strcspn(result, "\n")] = '\0';  // Ensure it ends with a newline
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "eth0.%d", vlan);
        if (strcmp(result, cmd) == 0) {
            printf("Only eth0. is present\n");
            del_vlan_frm_network(vlan);
            del_vlan_frm_firewall(vlan);
        }
    }

    return;    
}
#else
void del_wiface_frm_vlan_network(int vlan, char *section_name)
{
    int rc;
    char cmd[256];
    char result[128];    
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del_list network.%d.wiface=%s", vlan, section_name);
    rc = system(cmd);
    rc = system("uci commit network");
    if (rc != 0) {
        fprintf(stderr, "Failed to commit Network changes\n");
    }
    
    /*check if the wiface list is empty
      if empty delete the vlan network 
      and firewall */
    sprintf(cmd, "uci get network.%d.wiface", vlan);
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        if (strlen(result) == 0 || strstr(result, "Entry not found") != NULL) {
            del_vlan_frm_network(vlan);
            del_vlan_frm_firewall(vlan);
        }
    }

    return;    
}
#endif

#ifdef CONFIG_PLATFORM_MTK_JEDI
void check_existing_vlan(const char *section_name)
{
    char cmd[256];
    char result[128];    
    int vlan;

    //First check if there is existing vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci show network | grep -E 'ifname=.*\\b%s\\b' | awk -F'.' '{print $2}'", section_name);
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        // Check if the result is empty
        if (strlen(result) == 0 || strstr(result, "Entry not found") != NULL) {
            return;  // vlan is empty
        } 
        
        vlan = atoi(result);
        if (vlan == 0) {
            return;
        }
        
        /* if there is existing vlan
           delete it from the vlan 
           interface list */
        del_wiface_frm_vlan_network(vlan, (char *)section_name);     
        //set network flag
        //set_flag(&flags, FLAG_NETWORK_CHANGE);
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "ifup %d", vlan);
        system(cmd); 
    }

    return;
}
#else
void check_existing_vlan(char *section_name)
{
    int rc;
    char cmd[256];
    char result[128];    
    int vlan;

    //First check if there is existing vlan
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci get wireless.%s.vlan", section_name);
    if (execute_uci_command(cmd, result, sizeof(result)) == 0) {
        // Check if the result is empty
        if (strlen(result) == 0 || strstr(result, "Entry not found") != NULL) {
            return;  // vlan is empty
        } 
        
        vlan = atoi(result);
        if (vlan == 0) {
            return;
        }
        
        /* if there is existing vlan
           delete it from the vlan 
           interface list */
        del_wiface_frm_vlan_network(vlan, (char *)section_name);        
    
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "uci del wireless.%s.vlan", section_name);
        rc = system(cmd);
        rc = system("uci commit wireless");
        if (rc != 0) {
            fprintf(stderr, "Failed to commit wireless changes\n");
        }
    }

    return;
}
#endif
