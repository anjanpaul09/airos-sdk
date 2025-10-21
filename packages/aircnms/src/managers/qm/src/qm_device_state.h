#ifndef DEVICE_STATE_H
#define DEVICE_STATE_H

#include <pthread.h>

// -------------------------------
// Device state enum
// -------------------------------
typedef enum {
    DEVICE_STATE_DISCOVERY = 0,
    DEVICE_STATE_NOT_REGISTERED,
    DEVICE_STATE_REGISTERED
} device_state_t;

// -------------------------------
// Context structure
// -------------------------------
typedef struct {
    device_state_t current_state;
    pthread_mutex_t lock;
} device_context_t;

// -------------------------------
// API
// -------------------------------
void device_state_init(void);
void device_state_deinit(void);
void set_device_state(device_state_t new_state);
device_state_t get_device_state(void);
const char *device_state_to_string(device_state_t s);

// -------------------------------
// Helper to perform actions when state changes
// -------------------------------
void handle_device_state_change(device_state_t state);

#endif // DEVICE_STATE_H

