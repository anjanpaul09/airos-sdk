#include "sm.h"

void fill_dummy_device_report(dpp_device_report_data_t *report) {
    if (!report) return;

    memset(report, 0, sizeof(dpp_device_report_data_t));

    // Fill timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    report->timestamp_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;

    // Dummy Load averages
    report->record.load[0] = 0.5;
    report->record.load[1] = 1.2;
    report->record.load[2] = 2.3;

    // Dummy Uptime
    report->record.uptime = 123456; // Example uptime in seconds

    // Dummy Memory utilization
    report->record.mem_util.mem_total = 2048000; // 2 GB
    report->record.mem_util.mem_used = 1024000; // 1 GB
    report->record.mem_util.swap_total = 102400; // 100 MB
    report->record.mem_util.swap_used = 51200;  // 50 MB

    // Dummy CPU utilization
    report->record.cpu_util.cpu_util = 25; // 25%

    // Dummy Filesystem utilization
    report->record.fs_util[0].fs_type = 0; // Root FS
    report->record.fs_util[0].fs_total = 512000; // 500 MB
    report->record.fs_util[0].fs_used = 256000; // 250 MB

    report->record.fs_util[1].fs_type = 1; // Temp FS
    report->record.fs_util[1].fs_total = 102400; // 100 MB
    report->record.fs_util[1].fs_used = 51200;  // 50 MB

    // Dummy Power supply info
    report->record.power_info.ps_type = 0; // AC power
    report->record.power_info.p_consumption = 100; // 100W
    report->record.power_info.batt_level = 90; // 90%

    // Dummy top processes (CPU)
    report->record.n_top_cpu = 2; // Two top processes
    report->record.top_cpu[0].pid = 1234;
    strcpy(report->record.top_cpu[0].cmd, "process1");
    report->record.top_cpu[0].util = 20; // 20% CPU

    report->record.top_cpu[1].pid = 5678;
    strcpy(report->record.top_cpu[1].cmd, "process2");
    report->record.top_cpu[1].util = 15; // 15% CPU

    // Dummy top processes (Memory)
    report->record.n_top_mem = 2; // Two top processes
    report->record.top_mem[0].pid = 1234;
    strcpy(report->record.top_mem[0].cmd, "process1");
    report->record.top_mem[0].util = 204800; // 200 MB

    report->record.top_mem[1].pid = 5678;
    strcpy(report->record.top_mem[1].cmd, "process2");
    report->record.top_mem[1].util = 102400; // 100 MB
}

void dpp_dummy_get_device_report_data(dpp_device_report_data_t *report_ctx)
{
    bool rc;

    //report_ctx->timestamp_ms = get_current_timestamp_ms();
    fill_dummy_device_report(report_ctx);
    //rc = target_stats_device_get(report_ctx->record);
    if (true != rc) {
        return;
    }
}
