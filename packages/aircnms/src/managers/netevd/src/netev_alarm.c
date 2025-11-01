#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "device_config.h"

#include "log.h"
#include "memutil.h"

#define THRESHOLD 50 // Threshold for memory usage in percentage
#define CHECK_INTERVAL 5 // Interval between checks in seconds

int netev_check_alarm(uint8_t * buff, size_t sz, uint32_t * packed_sz)
{
    alarm_msg_t alarm;
    __attribute__((unused)) size_t tmp_packed_size; /* packed size of current report */
   
    strcpy(alarm.type, "reboot");
    strcpy(alarm.reason, "Not found");


    return 0;
}

// Function to calculate memory usage in percentage
int get_memory_usage() 
{
    FILE *file = fopen("/proc/meminfo", "r");
    if (!file) {
        perror("Could not open /proc/meminfo");
        return -1;
    }

    long total_mem = 0;
    long free_mem = 0;
    long available_mem = 0;
    char line[256];

    // Read /proc/meminfo line by line and get total, free, and available memory
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "MemTotal: %ld kB", &total_mem) == 1) {
            continue;
        }
        if (sscanf(line, "MemFree: %ld kB", &free_mem) == 1) {
            continue;
        }
        if (sscanf(line, "MemAvailable: %ld kB", &available_mem) == 1) {
            break;
        }
    }

    fclose(file);

    if (total_mem == 0) {
        fprintf(stderr, "Error: Unable to read total memory.\n");
        return -1;
    }

    // Calculate the percentage of memory used
    long used_mem = total_mem - available_mem;
    int usage_percent = (used_mem * 100) / total_mem;

    return usage_percent;
}

int check_memory_alarm() 
{
        int usage_percent = get_memory_usage();
        if (usage_percent < 0) {
            fprintf(stderr, "Error reading memory usage.\n");
            return 1;
        }

        printf("Memory usage: %d%%\n", usage_percent);

        // Check if memory usage exceeds the threshold
        if (usage_percent > THRESHOLD) {
            printf("ALARM: Memory usage exceeded %d%%!\n", THRESHOLD);
            // Add any additional alarm handling code here, such as logging or notifying
        }

    return 0;
}

// Function to parse CPU times from /proc/stat
int parse_cpu_times(long long *total, long long *idle) 
{
    FILE *file = fopen("/proc/stat", "r");
    if (!file) {
        perror("Could not open /proc/stat");
        return -1;
    }

    // Read the first line with "cpu" aggregate usage stats
    char line[256];
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return -1;
    }
    fclose(file);

    // Parse CPU time values
    long long user, nice, system, idle_time, iowait, irq, softirq, steal;
    if (sscanf(line, "cpu %lld %lld %lld %lld %lld %lld %lld %lld",
               &user, &nice, &system, &idle_time, &iowait, &irq, &softirq, &steal) < 4) {
        return -1;
    }

    *idle = idle_time;
    *total = user + nice + system + idle_time + iowait + irq + softirq + steal;
    return 0;
}

// Function to calculate CPU usage percentage
int get_cpu_usage() 
{
    long long total1, idle1, total2, idle2;

    // Read initial CPU times
    if (parse_cpu_times(&total1, &idle1) < 0) {
        fprintf(stderr, "Error reading CPU times\n");
        return -1;
    }
    sleep(1);

    // Read CPU times after a delay
    if (parse_cpu_times(&total2, &idle2) < 0) {
        fprintf(stderr, "Error reading CPU times\n");
        return -1;
    }

    // Calculate CPU usage as percentage
    long long total_diff = total2 - total1;
    long long idle_diff = idle2 - idle1;
    if (total_diff == 0) return 0;

    int usage_percent = (100 * (total_diff - idle_diff)) / total_diff;
    return usage_percent;
}

int check_cpu_alarm() 
{
        int usage_percent = get_cpu_usage();
        if (usage_percent < 0) {
            fprintf(stderr, "Error calculating CPU usage\n");
            return 1;
        }

        printf("CPU usage: %d%%\n", usage_percent);

        // Check if CPU usage exceeds the threshold
        if (usage_percent > THRESHOLD) {
            printf("ALARM: CPU usage exceeded %d%%!\n", THRESHOLD);
            // Add additional alarm handling code here, such as logging or notifying
        }

    return 0;
}
