#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "os_time.h"
#include "os_nif.h"
#include "log.h"

#include "qm_conn.h"
#include "sm.h"

#define STATS_MQTT_BUF_SZ        (128*1024)    // 128 KB
#define SM_QM_INTERVAL 1.0
/* Global MQTT instance */
static struct ev_timer  sm_mqtt_timer;
static double           sm_mqtt_timer_interval = SM_QM_INTERVAL;
//static uint8_t          sm_mqtt_buf[STATS_MQTT_BUF_SZ];

void sm_restart_qm_process() 
{
    FILE *fp;
    char pid_str[16];
    char kill_cmd[32];

    // Get the PID of the process
    fp = popen("pidof qm", "r");
    if (fp == NULL) {
        perror("Failed to run pidof command");
        return;
    }

    // Read the PID
    if (fgets(pid_str, sizeof(pid_str), fp) != NULL) {
        // Prepare the kill command
        snprintf(kill_cmd, sizeof(kill_cmd), "kill -9 %s", pid_str);
        LOG(INFO, "Executing: %s", kill_cmd);

        // Execute the kill command
        system(kill_cmd);
    } else {
        LOG(INFO, "No process found for /usr/sbin/qm\n");
    }

    pclose(fp);
    return;
}

bool sm_mqtt_publish(long mlen, void *mbuf)
{
    qm_response_t res;
    bool ret;
    int retry_count = 0;
    const int max_retries = 3;

    strcpy(res.tag, "stats");

    while (retry_count < max_retries) {
        ret = qm_conn_send_direct(QM_REQ_COMPRESS_DISABLE, NULL, mbuf, mlen, &res);

        if (ret) {
            return true; // Success, exit early
        }

        sm_restart_qm_process(); // needs optimization
        usleep(2000000);
        LOG(INFO, "SM: qm FAILED on attempt %d!!!!\n", retry_count + 1);
        retry_count++;
    }

    // If all retries failed
    LOG(INFO, "SM: qm FAILED after %d attempts!!!!\n", max_retries);

    return false;
}

void sm_mqtt_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

}

bool sm_mqtt_init(void)
{
    ev_timer_init(&sm_mqtt_timer, sm_mqtt_timer_handler, sm_mqtt_timer_interval, sm_mqtt_timer_interval);

    sm_mqtt_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &sm_mqtt_timer);

    return true;
}
