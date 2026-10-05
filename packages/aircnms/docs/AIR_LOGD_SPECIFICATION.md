# AIROS Logging Daemon (`air-logd`) Specification & Architecture Design

**Version:** 1.0.0  
**Target Platform:** MediaTek MT7621 (OpenWrt / Linux 5.x)  
**Package:** `aircnms` (`packages/aircnms/src/managers/logd`)  
**Status:** Approved Architecture Draft  

---

## 1. Overview & Purpose

`air-logd` is a dedicated, lightweight logging and log-rotation manager for the AIROS platform. It aggregates log output across all AIROS proprietary managers (`air-onbd`, `air-cgwd`, `air-netconfd`, `air-stamond`, etc.) and critical system services (`hostapd`, `dnsmasq`, `netifd`), enforces strict memory ceilings via continuous size-based log rotation, protects SPI flash wear, and provides an RPC query interface over `ubus`.

---

## 2. Production Design Gaps & Mitigations

During embedded production hardening, the following 8 design gaps were identified and addressed in this specification:

| # | Production Design Gap | Potential Failure / Risk | Architectural Mitigation in `air-logd` |
|---|----------------------|---------------------------|----------------------------------------|
| **1** | **Ubox Daemon Disconnect / Restart** | If `ubox-logd` crashes or starts after `air-logd`, the log stream is permanently lost. | Implement `ubus_event_handler` watching for `ubus.object.add` / `remove` for `"log"`. Auto-reconnect with exponential backoff. |
| **2** | **Concurrent Compression Spikes (OOM / CPU)** | Rapid log floods trigger multiple simultaneous `gzip` background processes, exhausting CPU cores and triggering kernel OOM. | Implement a **Single-Worker Compression Lock**. If compression is in progress, queue sequentially; spawn background worker with `nice -n 19`. |
| **3** | **Log Flooding / Rate Limiting** | Runaway crash loops or interface flapping spams thousands of messages/sec, saturating I/O and RAM. | **Token-Bucket Rate Limiter** per tag (e.g. max 50 msg/sec, burst 100). Emits suppression warning when exceeded. |
| **4** | **RAM / `tmpfs` Exhaustion** | If `/tmp` is consumed by firmware updates or core dumps, active logging causes a kernel panic. | Check available `/tmp` capacity (`statvfs`). If free space drops below safety margin (5 MB), halt rotation and purge oldest archive. |
| **5** | **UBUS RPC Buffer Overload** | Client requests `read {"lines": 100000}`, allocating excessive memory for `blobmsg` and crashing the daemon. | Enforce hard clamp: `lines = min(requested, 500)`. Implement efficient reverse-seek (`tail` style) reading without full-file RAM loading. |
| **6** | **Flash Wear vs Reboot Persistence** | Normal logs in `/tmp` vanish on reboot, leaving no post-mortem diagnostics after unexpected reboots. | **Dual-Tier Model**: Normal logs stay in RAM. On graceful reboot/panic hook, sync exactly one compressed crash bundle (`last_crash.gz`, max 100 KB) to `/overlay/etc/airos/`. |
| **7** | **System Clock Jumps (NTP)** | Embedded board boots in 1970 (or build epoch). NTP sync causes timestamps to leap forward years, breaking time-based rotation. | Pure size-based rotation (independent of wall time). Format logs with both monotonic elapsed time and wall-clock time; log explicit `[CLOCK_SYNC]` event on jump. |
| **8** | **Thread Safety & Ubus Deadlocks** | Multi-threaded ubus daemons frequently deadlock in embedded OpenWrt due to libubus concurrency limitations. | Strictly **Single-Threaded Event Loop** based on `libev`. Asynchronous background compression uses `fork()`/`execvp()` with `ev_child` watcher. |

---

## 3. Configuration Specification: `/etc/config/aircnms`

Configuration is consolidated within the central `/etc/config/aircnms` UCI file under `config logd 'logd'`:

```sh
config logd 'logd'
    option enabled '1'
    option log_dir '/tmp/logs/airos'
    option log_file 'airos.log'
    option max_size_kb '256'
    option max_backups '3'
    option compress '1'
    option min_severity 'info'
    option rate_limit_enable '1'
    option rate_limit_burst '100'
    option rate_limit_rate '50'
    list tag 'air-onbd'
    list tag 'air-cgwd'
    list tag 'air-netconfd'
    list tag 'air-stamond'
    list tag 'air-eventd'
    list tag 'air-netstatsd'
    list tag 'airuid'
    list tag 'air-cmdexecd'
    list tag 'air-onbd-recovery'
    list tag 'air-ssid-check'
    list tag 'air_led_state'
    list tag 'hostapd'
    list tag 'netifd'
    list tag 'dnsmasq'
```

---

## 4. Software Architecture & Modules

```
packages/aircnms/src/managers/logd/
├── Makefile
├── inc/
│   ├── logd.h            # Main manager context & types
│   ├── logd_config.h     # UCI configuration loader
│   ├── logd_filter.h     # Tag allowlist, rate limiting, formatting
│   ├── logd_rotate.h     # High-efficiency file writer & rotation
│   ├── logd_stream.h     # Ubox log stream client & reconnect logic
│   └── logd_ubus.h       # UBUS air.log RPC API
└── src/
    ├── main.c            # libev event loop, signals, startup
    ├── logd_config.c     # libuci reader for aircnms.logd
    ├── logd_filter.c     # Token-bucket rate limiter & tag matcher
    ├── logd_rotate.c     # Atomic rename, size tracking, gzip worker
    ├── logd_stream.c     # Async ubus subscriber to ubox "log"
    └── logd_ubus.c       # RPC dispatchers (status, read, rotate, clear)
```

### 4.1 Ingestion Engine (`logd_stream.c`)
- Connects to OpenWrt `ubox-logd` via ubus method `log read {"stream": true}`.
- Parses incoming blobmsg attributes (`msg`, `source`, `priority`, `time`).
- Subscribes to ubus object notifications: if `log` unregisters/registers, automatically handles teardown and re-subscription.

### 4.2 Filter & Rate Limiter (`logd_filter.c`)
- **Allowlist Prefix Matching**: Evaluates incoming message tag against configured `tag` list.
- **Token Bucket Rate Limiting**: Maintains a hash-table / array of token buckets per tag:
  - Replenishes tokens at `rate_limit_rate` tokens/sec.
  - Drops logs if bucket reaches 0; outputs suppression summaries every 10 seconds.
- **Formatter**: Prepares structured, human-readable entries:
  ```text
  YYYY-MM-DD HH:MM:SS [TAG] [SEVERITY] (PID): MESSAGE
  ```

### 4.3 Rotation Engine (`logd_rotate.c`)
- Maintains open file descriptor to `${log_dir}/${log_file}` with `O_APPEND | O_CREAT | O_WRONLY`.
- Tracks `bytes_written` in memory.
- When `bytes_written >= max_size_bytes`:
  1. `fflush()` and `close()`.
  2. If file `airos.log.<max_backups>.gz` exists $\rightarrow$ `unlink()`.
  3. Shift intermediate archives: `.2.gz` $\rightarrow$ `.3.gz`, `.1.gz` $\rightarrow$ `.2.gz`.
  4. Rename active log: `rename("airos.log", "airos.log.1")`.
  5. Open fresh `airos.log` immediately with `O_TRUNC` and reset `bytes_written = 0` (zero dropped logs).
  6. Trigger background compression on `airos.log.1` via `posix_spawn()` calling `/bin/gzip -f -9`.
  7. Use `ev_child` in libev loop to reap child process without blocking the event loop.

### 4.4 UBUS RPC Interface (`logd_ubus.c`)

Object Name: **`air.log`**

#### Methods:
1. **`status`**
   - **Input**: `{}`
   - **Output**:
     ```json
     {
       "enabled": true,
       "active_file": "/tmp/logs/airos/airos.log",
       "active_size_bytes": 142100,
       "max_size_bytes": 262144,
       "backup_count": 3,
       "total_rotations": 5,
       "messages_processed": 18240,
       "messages_dropped_rate_limit": 12,
       "compress_active": false
     }
     ```
2. **`read`**
   - **Input**: `{"lines": 50, "tag": "air-onbd"}` (lines clamped: 1–500)
   - **Output**:
     ```json
     {
       "count": 50,
       "lines": [
         "2026-09-30 18:00:01 [air-onbd] [INFO]: visible_state=OPERATIONAL",
         "2026-09-30 18:00:06 [air-onbd] [INFO]: visible_state=OPERATIONAL"
       ]
     }
     ```
3. **`rotate`**
   - **Input**: `{}`
   - **Output**: `{"result": "ok"}`
   - **Description**: Triggers an immediate rotation regardless of current file size.
4. **`clear`**
   - **Input**: `{}`
   - **Output**: `{"result": "ok"}`
   - **Description**: Truncates the active log and deletes all `.gz` archives.

---

## 5. Procd Init Script: `/etc/init.d/airlogd`

```sh
#!/bin/sh /etc/rc.common

START=12
STOP=88
USE_PROCD=1
PROG=/usr/sbin/air-logd

start_service() {
    local enabled=$(uci -q get aircnms.logd.enabled || echo "1")
    [ "$enabled" = "1" ] || return 0

    local log_dir=$(uci -q get aircnms.logd.log_dir || echo "/tmp/logs/airos")
    mkdir -p "$log_dir"

    procd_open_instance
    procd_set_param command "$PROG"
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger aircnms
}

stop_service() {
    # Optional shutdown crash hook: save last archive to persistent storage if clean shutdown
    local log_dir=$(uci -q get aircnms.logd.log_dir || echo "/tmp/logs/airos")
    if [ -f "$log_dir/airos.log.1.gz" ]; then
        mkdir -p /overlay/etc/airos/log_backup 2>/dev/null || true
        cp -f "$log_dir/airos.log.1.gz" /overlay/etc/airos/log_backup/last_boot.log.gz 2>/dev/null || true
    fi
}
```

---

## 6. Build System & Packaging Integration

In `packages/aircnms/Makefile`:

1. **Manager Definition**:
   ```makefile
   BUILD_MGRLOGD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/logd $(MAKE_PACKAGE_ARGS)
   ```
2. **Compilation**:
   ```makefile
   define Build/Compile
       ...
       $(BUILD_MGRLOGD)
   endef
   ```
3. **Installation**:
   ```makefile
   define Package/aircnms/install
       ...
       $(INSTALL_BIN) ./files/airlogd $(1)/etc/init.d/
       $(CP) $(PKG_BUILD_DIR)/managers/logd/logd $(1)/usr/sbin/air-logd
   endef
   ```

---

## 7. Verification Test Suite

1. **Daemon Lifecycle & Procd**:
   - `ps | grep air-logd` shows active instance.
   - Kill process with `kill -9`; confirm procd restarts daemon within 5 seconds.
2. **Ingestion & Tag Filtering**:
   - Emit test log: `logger -t air-onbd "Test onboarding log message"`
   - Confirm message appears in `/tmp/logs/airos/airos.log`.
   - Emit non-matching log: `logger -t random_app "Ignored message"`
   - Confirm message is discarded.
3. **Rotation Stress Test**:
   - Generate 1 MB of synthetic logs via script:
     ```sh
     for i in $(seq 1 5000); do logger -t air-onbd "Stress log test line $i"; done
     ```
   - Confirm active log never exceeds `256 KB`.
   - Confirm `airos.log.1.gz`, `airos.log.2.gz`, `airos.log.3.gz` are created.
   - Confirm `gzip -t` validates archive integrity.
4. **Rate Limiting Verification**:
   - Flood 1,000 logs in 1 second; verify rate suppression message is logged and CPU utilization does not exceed safe limits.
5. **UBUS RPC Testing**:
   - Run `ubus call air.log status` and verify JSON keys.
   - Run `ubus call air.log read '{"lines": 10}'` and verify log line array.
   - Run `ubus call air.log rotate` and confirm manual rotation triggers cleanly.
