#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/vfs.h>

#include "util.h"
#include "log.h"
#include "report.h"
//#include "osp_power.h"
#include "memutil.h"

#ifdef CONFIG_PLATFORM_MTK_JEDI
#include "ioctl80211_jedi.h"
#endif

#define MODULE_ID LOG_MODULE_ID_TARGET

#define LINUX_PROC_LOADAVG_FILE  "/proc/loadavg"
#define LINUX_PROC_UPTIME_FILE   "/proc/uptime"
#define LINUX_PROC_MEMINFO_FILE  "/proc/meminfo"
#define LINUX_PROC_STAT_FILE     "/proc/stat"

#define STR_BEGINS_WITH(buf, token)  \
            (strncmp(buf, token, strlen(token)) == 0)


#define PID_BUF_NUM      128

typedef struct
{
    uint32_t   pid;
    char       cmd[18];

    uint32_t   utime;       // [clock ticks]
    uint32_t   stime;       // [clock ticks]
    uint64_t   starttime;   // [clock ticks]

    uint32_t   rss;         // [kB]
    uint32_t   pss;         // [kB]

    uint32_t   mem_util;    // Memory usage estimation [kB]
    uint32_t   cpu_util;    // CPU utilization [%] [0..100]
} pid_util_t;

typedef struct
{
    uint64_t     timestamp;   // [clock ticks]

    pid_util_t  *pid_util;
    unsigned     n_pid_util;

    uint32_t     mem_total;   // System memory size [kB]
    uint32_t     mem_used;    // System memory used [kB]
    uint32_t     swap_total;  // Swap file size [kB]
    uint32_t     swap_used;   // Swap file used [kB]
} system_util_t;

typedef struct
{
    uint64_t hz_user;
    uint64_t hz_nice;
    uint64_t hz_system;
    uint64_t hz_idle;
} cpu_stats_hz_t;

/* Defaults. Values will be acquired at runtime, although they will likely
 * match the defaults set here. */
static uint32_t PAGE_KB   =    4;
static uint32_t CLOCK_TCK =  100;
static cpu_stats_hz_t  g_cpu_stats_prev;
//static system_util_t   g_sysutil_prev;

static bool linux_device_uptime_get(device_record_t *record)
{
    int32_t     rc;
    const char  *filename = LINUX_PROC_UPTIME_FILE;
    FILE        *proc_file = NULL;

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        LOG(ERR, "Parsing device stats (Failed to open %s)", filename);
        return false;
    }

    rc = fscanf(proc_file, "%u", &record->uptime);

    fclose(proc_file);

    if (rc != 1)
    {
        LOG(ERR, "Parsing device stats (Failed to read %s)", filename);
        return false;
    }

    LOG(TRACE, "Parsed device uptime %u", record->uptime);

    return true;
}

static int proc_parse_meminfo(system_util_t *system_util)
{
    const char *filename = LINUX_PROC_MEMINFO_FILE;
    FILE *proc_file = NULL;
    char buf[256];
    uint32_t mem_total;
    uint32_t mem_avail;
    uint32_t mem_free;
    uint32_t swap_total;
    uint32_t swap_free;


    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        LOG(ERROR, "Failed opening file: %s", filename);
        return -1;
    }

    while (fgets(buf, sizeof(buf), proc_file) != NULL)
    {
        if (STR_BEGINS_WITH(buf, "MemTotal:"))
        {
            if (sscanf(buf, "MemTotal: %u", &mem_total) != 1)
                goto parse_error;
        }
        else if (STR_BEGINS_WITH(buf, "MemFree:"))
        {
            if (sscanf(buf, "MemFree: %u", &mem_free) != 1)
                goto parse_error;
        }
        else if (STR_BEGINS_WITH(buf, "MemAvailable:"))
        {
            if (sscanf(buf, "MemAvailable: %u", &mem_avail) != 1)
                goto parse_error;
        }
        else if (STR_BEGINS_WITH(buf, "SwapTotal:"))
        {
            if (sscanf(buf, "SwapTotal: %u", &swap_total) != 1)
                goto parse_error;
        }
        else if (STR_BEGINS_WITH(buf, "SwapFree:"))
        {
            if (sscanf(buf, "SwapFree: %u", &swap_free) != 1)
                goto parse_error;
        }
    }

    system_util->mem_total = mem_total;
    if (mem_avail > 0) {
        system_util->mem_used = mem_total - mem_avail;
    } else {
        system_util->mem_used = mem_total - mem_free;   /* older kernels */
    }

    system_util->swap_total = swap_total;
    system_util->swap_used  = swap_total - swap_free;

    fclose(proc_file);
    return 0;

parse_error:
    fclose(proc_file);
    LOG(ERROR, "Error parsing %s.", filename);
    return -1;
}


static bool linux_device_memutil_get(device_memutil_t *memutil)
{
    system_util_t system_util;

    if (proc_parse_meminfo(&system_util) != 0)
    {
        return false;
    }

    memset(memutil, 0, sizeof(*memutil));

    memutil->mem_total  = system_util.mem_total;
    memutil->mem_used   = system_util.mem_used;
    memutil->swap_total = system_util.swap_total;
    memutil->swap_used  = system_util.swap_used;

    return true;
}

static bool linux_device_fsutil_get(device_fsutil_t *fsutil)
{
    const char *path;
    struct statfs fs_info;
    int rc;


    switch (fsutil->fs_type)
    {
        case DEVICE_FS_TYPE_ROOTFS:
            path = "/";
            break;
        case DEVICE_FS_TYPE_TMPFS:
            path = "/tmp";
            break;
        default:
            LOG(ERROR, "Invalid fs type: %d", fsutil->fs_type);
            return false;
    }


    rc = statfs(path, &fs_info);
    if (rc != 0)
    {
        LOG(ERROR, "Error getting filesystem status info: %s: %s", path, strerror(errno));
        return false;
    }

    fsutil->fs_total = (fs_info.f_blocks * fs_info.f_bsize) / 1024;
    fsutil->fs_used = ((fs_info.f_blocks - fs_info.f_bfree) * fs_info.f_bsize) / 1024;

    return true;
}

static bool linux_device_cpuutil_get(device_cpuutil_t *cpuutil)
{
    const char *filename = LINUX_PROC_STAT_FILE;
    FILE *proc_file = NULL;
    char buf[256] = { 0 };


    memset(cpuutil, 0, sizeof(*cpuutil));

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        LOG(ERROR, "Failed opening file: %s", filename);
        return false;
    }

    while (fgets(buf, sizeof(buf), proc_file) != NULL)
    {
        cpu_stats_hz_t now;
        cpu_stats_hz_t diff;
        uint64_t hz_total_diff;
        double busy;

        /* Check for 'cpu', but not 'cpu0', 'cpu1', and such */
        if (!STR_BEGINS_WITH(buf, "cpu ")) continue;  // not the right line

        if (sscanf(buf, "cpu %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"",
                    &(now.hz_user), &(now.hz_nice), &(now.hz_system), &(now.hz_idle)) != 4)
        {
            goto parse_error;
        }

        diff.hz_user   = now.hz_user   - g_cpu_stats_prev.hz_user;
        diff.hz_nice   = now.hz_nice   - g_cpu_stats_prev.hz_nice;
        diff.hz_system = now.hz_system - g_cpu_stats_prev.hz_system;
        diff.hz_idle   = now.hz_idle   - g_cpu_stats_prev.hz_idle;

        g_cpu_stats_prev = now;  // store current values

        hz_total_diff = diff.hz_user
                        + diff.hz_nice
                        + diff.hz_system
                        + diff.hz_idle;

        if (hz_total_diff == 0)
        {
            LOG(ERROR, "%s: Unexpected hz_total value: %"PRIu64"",
                        __func__, hz_total_diff);
            return false;
        }

        /* Calculate percentage and round */
        busy = (1.0 - ((double)diff.hz_idle / (double)hz_total_diff)) * 100.0;

        cpuutil->cpu_util = (uint32_t) (busy + 0.5);

        break;  // found the aggregate 'cpu' line, exit loop
    }

    fclose(proc_file);
    return true;

parse_error:
    fclose(proc_file);
    LOG(ERROR, "Error parsing %s.", filename);
    return false;
}

bool linux_device_wifi_util_get(device_wifiutil_t *w_util)
{
    vif_record_t vif_record;

    memset(&vif_record, 0, sizeof(vif_record_t));

    w_util->num_sta = 0;

#ifdef CONFIG_PLATFORM_MTK_JEDI
    if (ioctl80211_jedi_stats_vap_get(&vif_record)) {
        for (int i = 0; i < vif_record.n_vif; i++) {
            w_util->num_sta += vif_record.vif[i].num_sta;
            w_util->uplink_mb += vif_record.vif[i].uplink_mb;
            w_util->downlink_mb += vif_record.vif[i].downlink_mb;
        }
    }
#endif

#ifdef CONFIG_PLATFORM_MTK
    if (nl80211_stats_vap_get(&vif_record)) {
        for (int i = 0; i < vif_record.n_vif; i++) {
            w_util->num_sta += vif_record.vif[i].num_sta;
            w_util->uplink_mb += vif_record.vif[i].uplink_mb;
            w_util->downlink_mb += vif_record.vif[i].downlink_mb;
        }
    }
#endif
    w_util->total_traffic_mb = w_util->uplink_mb + w_util->downlink_mb;
    return true;
}

int target_stats_device_get(device_record_t *device_entry)
{

    int i;
    long rc;


    /* Get actual values at runtime for page size and USER_HZ,
     * although they probably do not differ from default */
    if ((rc = sysconf(_SC_PAGESIZE)) != -1)
    {
        PAGE_KB = (uint32_t)(rc/1024);
    }
    if ((rc = sysconf(_SC_CLK_TCK)) != -1)
    {
        CLOCK_TCK = (uint32_t)rc;
    }

    if (!linux_device_uptime_get(device_entry))
    {
        LOG(ERR, "Failed to retrieve device uptime.");
        return false;
    }
    if (!linux_device_memutil_get(&device_entry->mem_util))
    {
        LOG(ERR, "Failed to retrieve device memory utilization.");
        return false;
    }
    if (!linux_device_cpuutil_get(&device_entry->cpu_util))
    {
        LOG(ERR, "Failed to retrieve device cpu utilization.");
        return false;
    }
    if (!linux_device_wifi_util_get(&device_entry->w_util))
    {
        LOG(ERR, "Failed to retrieve device wifi utilization.");
        return false;
    }

    device_entry->fs_util[DEVICE_FS_TYPE_ROOTFS].fs_type = DEVICE_FS_TYPE_ROOTFS;
    device_entry->fs_util[DEVICE_FS_TYPE_TMPFS].fs_type = DEVICE_FS_TYPE_TMPFS;
    for (i = 0; i < DEVICE_FS_TYPE_QTY; i++)
    {
        if (!linux_device_fsutil_get(&device_entry->fs_util[i]))
        {
            LOG(ERR, "Failed to retrieve device filesystem utilization.");
            return false;
        }
    }

    return true;
}
