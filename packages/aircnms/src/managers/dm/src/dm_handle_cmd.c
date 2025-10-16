#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "log.h"
#include "dm.h"
#include <jansson.h>

#define COMMAND_SIZE 1024
char cmd_id[128];

// Handler functions
void handle_cmd_reboot(json_t *root) 
{
    char cmd[32];
    strcpy(cmd, json_string_value(json_object_get(root, "cmd")));
 
    target_cmd_reboot(cmd);
}

void handle_cmd_device_delete(json_t *root) 
{
    char cmd[32];
    strcpy(cmd, json_string_value(json_object_get(root, "cmd")));
    
    target_cmd_device_delete(cmd);
}

void handle_cmd_device_upgrade(json_t *root) 
{
    memset(&fw_id, 0, sizeof(fw_id));
    strcpy(fw_id, json_string_value(json_object_get(root, "device_firmware_id")));
    set_fw_id_to_aircnms(fw_id);
    
    target_cmd_device_upgrade();
}

void handle_cmd_ping(json_t *root) 
{
    target_exec_cmd_ping("8.8.8.8");
}


void handle_cmd_arp(json_t *root) 
{
    target_exec_cmd_arp();
}

void handle_cmd_device_conf(json_t *root) 
{
    dm_monitor_config_change();
    
    memset(&cmd_id, 0, sizeof(cmd_id));
    strcpy(cmd_id, json_string_value(json_object_get(root, "device_web_cli_id")));
    
    target_exec_cmd_custom("uci show aircnms.@device[0] | cut -d'=' -f2 | tr -d \"'\"");
}

void handle_cmd_custom(json_t *root) 
{
    char command[COMMAND_SIZE];
    strcpy(command, json_string_value(json_object_get(root, "cmd")));
  
    if (strcmp(command, "get_device_conf") == 0) {
        printf("Matched get_device_conf\n");
        handle_cmd_device_conf(root);
        return;
    } 

    memset(&cmd_id, 0, sizeof(cmd_id));
    strcpy(cmd_id, json_string_value(json_object_get(root, "device_web_cli_id")));
    
    target_exec_cmd_custom(command);
}

CommandMapping commands[] = {
    {"reboot", handle_cmd_reboot},
    {"device_deleted", handle_cmd_device_delete},
    {"upgrade", handle_cmd_device_upgrade},
    //{"ping", handle_cmd_ping},
    //{"arp", handle_cmd_arp},
    {"custom", handle_cmd_custom},
    {NULL, NULL}  
};

int dm_process_cmd_msg(char* buf)
{
    json_error_t error;
    json_t *root = json_loads(buf, 0, &error);

    if (!root) {
        //fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return false;
    }

    const char *cmd = json_string_value(json_object_get(root, "cmd"));
    if (!cmd) {
        json_decref(root);
        return false;
    }
    LOG(INFO, "DM: Cloud Command: %s\n", cmd);
    printf("DM: Cloud Command: %s\n", cmd);

    bool handled = false;

    // Process command using the dispatch table
    for (int i = 0; commands[i].keyword != NULL; i++) {
        if (strstr(cmd, commands[i].keyword) != NULL) {
            commands[i].handler(root);
            handled = true;
            break;
        }
    }

    // If no match was found, handle it as a custom command
    if (!handled) {
        handle_cmd_custom(root);
    }

    json_decref(root);

    return 0;
}


