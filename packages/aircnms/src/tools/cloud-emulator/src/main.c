#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

/* Publish hook from mos_pub.c */
extern void on_config_file_changed(const char *dir, const char *name, const char *action);

/* Forward declarations from mos_sub.c (threaded API) */
int start_mqtt_subscriber_threaded(void);
void stop_mqtt_subscriber_threaded(void);

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_sigusr1 = 0;
static volatile sig_atomic_t g_sigusr2 = 0;

static void on_signal(int sig) {
  (void)sig;
  if (sig == SIGUSR1) {
    g_sigusr1 = 1;
  } else if (sig == SIGUSR2) {
    g_sigusr2 = 1;
  } else {
    g_stop = 1;
  }
}

int main(int argc, char **argv) 
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  const char *config_dir = NULL;
  if (argc > 1) {
    config_dir = argv[1];
  } else {
    config_dir = "config"; /* default relative directory */
  }

  struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = on_signal; sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL); sigaction(SIGUSR1, &sa, NULL); sigaction(SIGUSR2, &sa, NULL);

  int mqtt_rc = start_mqtt_subscriber_threaded();
  if (mqtt_rc != 0) {
    fprintf(stderr, "MQTT subscriber failed to start (rc=%d)\n", mqtt_rc);
  }

  fprintf(stdout, "cloud-emulator started (pid=%d). Send SIGUSR1 to push config, SIGUSR2 to push cmd. Press Ctrl+C to exit.\n", getpid());
  fflush(stdout);

  while (!g_stop) {
    if (g_sigusr1) {
      g_sigusr1 = 0;
      fprintf(stdout, "[signal] SIGUSR1 -> publish wifi.conf\n"); fflush(stdout);
      on_config_file_changed(config_dir, "wifi.conf", "signal");
    }
    if (g_sigusr2) {
      g_sigusr2 = 0;
      fprintf(stdout, "[signal] SIGUSR2 -> publish cmd.conf\n"); fflush(stdout);
      on_config_file_changed(config_dir, "cmd.conf", "signal");
    }
    sleep(1);
  }

  stop_mqtt_subscriber_threaded();
  return 0;
}


