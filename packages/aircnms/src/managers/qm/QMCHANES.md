## QM threading and queueing changes

This change introduces a decoupled producer/consumer design inside `qm` using a thread-safe queue and a dedicated MQTT worker thread.

- Unix domain socket server (libunixcomm) runs in the event loop thread and enqueues incoming messages into the shared queue.
- MQTT worker runs in a separate pthread and blocks on a condition variable until work arrives, then drains the queue and publishes to the broker.

### Key points

- Thread-safe queue backed by `ds_dlist_t` with `pthread_mutex_t` and `pthread_cond_t`.
- No message loss in-process: when queue is full, policy is to drop from head (oldest) respecting existing `QM_MAX_QUEUE_*` limits, and count drops in `qm_response_t.qdrop`.
- Multiple local producers supported: libunixcomm accepts multiple clients; each received message becomes one queue item.
- MQTT send is single-threaded to preserve ordering per process and keep mosquitto client usage simple.

### Files touched

- `src/qm.h`
  - Added `pthread` includes and declarations for `g_qm_queue_mutex` and `g_qm_queue_cond`.
  - Declared MQTT worker API and unixcomm server lifecycle prototypes.

- `src/qm_queue.c`
  - Added global mutex/cond initialization.
  - Protect enqueue/dequeue and signal condition on enqueue.

- `src/qm_mqtt.c`
  - Added MQTT worker thread that waits on the condition, reconnects if needed, and drains the queue using existing send helpers.
  - Exposed `qm_mqtt_start_worker()` and `qm_mqtt_stop_worker()`.

- `src/qm_unixcomm_server.c`
  - On receive, construct `qm_item_t`, copy topic and data, `qm_queue_put()`; message memory is then freed via `unixcomm_message_destroy()`.
  - Fixed client arrays to use `MAX_UNIXCOMM_CLIENTS`.

- `src/main.c`
  - Initialize queue, start MQTT worker, start unixcomm server, and stop worker on shutdown.

- `Makefile`
  - Link with `-lpthread`.

### Concurrency model

- Producers: unixcomm server callbacks in event loop thread push messages. Future producers can call `qm_queue_put()` as well.
- Consumer: single MQTT worker thread; ordering is FIFO according to queue order.
- Signaling: enqueue signals `g_qm_queue_cond`; worker waits when queue is empty.

### Operational notes

- Backpressure: when queue exceeds `QM_MAX_QUEUE_DEPTH` or `QM_MAX_QUEUE_SIZE_BYTES`, oldest entries are dropped to make room.
- Shutdown: `qm_mqtt_stop_worker()` broadcasts the cond to wake the worker and joins the thread.
- Timer-based publisher remains but worker performs immediate draining; timer can be kept as a safety net or removed later.

### Future improvements

- Optional multi-consumer partitioning per topic if required for throughput.
- Persist queue to disk for crash resilience.
- Metrics for queue length, drops, and publish latencies.


