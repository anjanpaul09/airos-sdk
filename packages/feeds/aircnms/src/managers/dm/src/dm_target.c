#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <stdbool.h>
#include "dm.h"
#include <jansson.h>

#define BUFFER_SIZE 10240
#define COMMAND_SIZE 1024
#define COMMAND_TIMEOUT 5  // seconds

static sigjmp_buf jump_env;

static void alarm_handler(int signo) 
{
    (void)signo;
    siglongjmp(jump_env, 1);
}

int target_reset_aircnms()
{
    char cmd[256];
    int rc;

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].online=0");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].device_id=XXXXXXXXXX");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].network_id=XXXXXXXXXX");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].org_id=XXXXXXXXXX");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@aircnms[0].username");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@aircnms[0].password");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@aircnms[0].topics");
    rc = system(cmd);
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@device[0].egress_ip");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@device[0].fw_version");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@device[0].hw_version");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@device[0].mgmt_ip");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@stats-topic[0].device");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@stats-topic[0].vif");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@stats-topic[0].client");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@stats-topic[0].neighbor");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@stats-topic[0].config");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci del aircnms.@stats-topic[0].cmdr");
    rc = system(cmd);

    rc = system("uci commit aircnms");

    return rc;

}

int target_reset_network()
{
    char cmd[256];
    int rc;

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
    sprintf(cmd, "uci set network.nat_network.ipaddr='192.168.23.1'");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set network.nat_network.netmask='255.255.255.0'");
    rc = system(cmd);

    rc = system("uci commit network");

    return rc;
}

int target_reset_wireless()
{
    char cmd[256];
    int rc;

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan1.ssid='Airpro2g'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan1.disabled=0");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan2.ssid='Airpro5g'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan2.disabled=0");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan3.ssid='Airpro2g-2'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan3.disabled=1");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan4.ssid='Airpro5g-2'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan4.disabled=1");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan5.ssid='Airpro2g-3'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan5.disabled=1");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan6.ssid='Airpro5g-3'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan6.disabled=1");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan7.ssid='Airpro2g-4'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan7.disabled=1");
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan8.ssid='Airpro5g-4'");
    rc = system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set wireless.wlan8.disabled=1");
    rc = system(cmd);

    rc = system("uci commit wireless");

    return rc;
}

int target_cmd_device_delete(char *command)
{
    int rc;

    rc = target_reset_wireless();        //RESET WIRELESS FILE
    rc = target_reset_network();        //RESET NETWORK FILE
    rc = target_reset_aircnms();         //RESET AIRCNMS FILE
    //system("cp -f /etc/config/factorydata/aircnms /etc/config/aircnms");
    //system("cp -f /etc/config/factorydata/wireless /etc/config/wireless");
#ifdef CONFIG_PLATFORM_MTK_JEDI
    system("cp -f /etc/config/factorydata/mt7915.dbdc.b0.dat /etc/wireless/mediatek/");
    system("cp -f /etc/config/factorydata/mt7915.dbdc.b1.dat /etc/wireless/mediatek/");
#endif
    rc= target_cmd_reboot("reboot");

    return rc;
}

int target_cmd_reboot(char *cmd)
{
    system(cmd);
    return 0;
}

bool exec_command(const char *command, char *output, size_t output_size)
{
    FILE *fp;
    char buffer[256];
    size_t total_length = 0;

    if (!command || !output || output_size == 0)
        return false;

    output[0] = '\0';

    // Setup timeout
    signal(SIGALRM, alarm_handler);

    if (sigsetjmp(jump_env, 1) != 0) {
        // Timeout occurred
        fprintf(stderr, "Command timed out: %s\n", command);
        return false;
    }

    alarm(COMMAND_TIMEOUT);  // Set timeout

    fp = popen(command, "r");
    if (!fp) {
        perror("popen failed");
        alarm(0);
        return false;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        if (total_length + len < output_size - 1) {
            strcat(output, buffer);
            total_length += len;
        } else {
            fprintf(stderr, "Output buffer exceeded\n");
            break;
        }
    }

    pclose(fp);
    alarm(0);  // Cancel timeout

    return true;
}

bool target_exec_cmd_ping(char *dest)
{
    char output[BUFFER_SIZE];
    char command[COMMAND_SIZE];

    memset(output, 0, sizeof (output)); 
    memset(command, 0, sizeof(command));

    sprintf(command, "ping -c 4 %s", dest);
    //exec_command(command, output, sizeof(output));

    if (!exec_command(command, output, sizeof(output))) {
        LOG(ERR, "DM: CMD FAILED - %s", command);
        strcpy(output, "ping failed or timed out\n");
    }

    printf("%s", output);
    dm_send_event_to_cloud(CMD, 0, output, cmd_id);    //sending status to cloud

    return true;
}

bool target_exec_cmd_arp()
{
    char output[BUFFER_SIZE];
    char command[COMMAND_SIZE];

    memset(output, 0, sizeof (output));
    memset(command, 0, sizeof(command));

    sprintf(command, "arp -a");
    //exec_command(command, output, sizeof(output));
    if (!exec_command(command, output, sizeof(output))) {
        LOG(ERR, "DM: CMD FAILED - %s", command);
        strcpy(output, "arp failed or timed out\n");
    }

    printf("%s", output);
    
    return true;
}


bool target_exec_cmd_custom(char *cmd)
{
    char output[BUFFER_SIZE];

    memset(output, 0, sizeof (output)); 
    
    if (!exec_command(cmd, output, sizeof(output))) {
        LOG(ERR, "DM: CMD FAILED - %s", cmd);
        strcpy(output, "cmd timed out\n");
    }

    printf("%s", output);
    dm_send_event_to_cloud(CMD, 0, output, cmd_id);    //sending status to cloud

    return true;
}

