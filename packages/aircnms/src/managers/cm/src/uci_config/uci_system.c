#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include "uci_ops.h"
#include <airpro_mgr_msg.h>

int uci_set_system_config(char *sec_name, struct airpro_mgr_system_config *system_config)
{
    int status;
    char *sec = sec_name;
    const char *pkg = {"system"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += strlen(system_config->radio0_vap_idx) ? uciSet(pkg, sec, "radio0_vap_idx", system_config->radio0_vap_idx) : 0;
        status += strlen(system_config->radio1_vap_idx) ? uciSet(pkg, sec, "radio1_vap_idx", system_config->radio1_vap_idx) : 0;
        status += strlen(system_config->network_mode) ? uciSet(pkg, sec, "network_mode", system_config->network_mode) : 0;
        status += strlen(system_config->mgmt_ip_set) ? uciSet(pkg, sec, "mgmt_ip_set", system_config->mgmt_ip_set) : 0;
        status += strlen(system_config->device_sn) ? uciSet(pkg, sec, "device_sn", system_config->device_sn) : 0;
        status += strlen(system_config->system_mode) ? uciSet(pkg, sec, "system_mode", system_config->system_mode) : 0;
        status += strlen(system_config->airpro_ctrler_msg_freq) ? uciSet(pkg, sec, "airpro_ctrler_msg_freq", system_config->airpro_ctrler_msg_freq) : 0;
        if (status)
            break;
        else
            status = uciCommit(pkg);

    } while(0);

    uciDestroy();
    return status;
}

int uci_get_system_config(char *sec_name, struct airpro_mgr_system_config *system_config)
{
    int status;
    char *sec = sec_name;
    const char *pkg = {"system"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += uciGet(pkg, sec, "radio0_vap_idx",  system_config->radio0_vap_idx);
        status += uciGet(pkg, sec, "radio1_vap_idx",  system_config->radio1_vap_idx);
        status += uciGet(pkg, sec, "network_mode",  system_config->network_mode);
        status += uciGet(pkg, sec, "mgmt_ip_set",  system_config->mgmt_ip_set);
        status += uciGet(pkg, sec, "controller_ip", system_config->controller_ip);
        status += uciGet(pkg, sec, "controller_port", system_config->controller_port);
        status += uciGet(pkg, sec, "agent_dump_interval", system_config->agent_dump_interval);
        status += uciGet(pkg, sec, "device_sn", system_config->device_sn);
        status += uciGet(pkg, sec, "system_mode", system_config->system_mode);
        status += uciGet(pkg, sec, "airpro_ctrler_msg_freq", system_config->airpro_ctrler_msg_freq);
        if (status)
            break;

    } while(0);

    uciDestroy();
    return status;
}



int uci_add_section_system_config(char *sec_type, char *sec_name)
{
    const char *pkg = {"system"};
    int status;

    status = uciInit();
    if (status != SUCCESS)
        return status;

    uciAddSection(pkg, sec_type, sec_name);

    uciCommit(pkg);

    uciDestroy();
    return status;

}
