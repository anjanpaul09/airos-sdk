# Process-Specific UnixComm API

## 🎯 **Problem Solved**

The user identified two key issues with the UnixComm library:

1. **Common flag for socket path**: Need a way to specify which process to communicate with
2. **pthread dependency**: The library shouldn't require pthread as a dependency

## 🔧 **Solutions Implemented**

### **1. Process-Specific Socket Paths**

#### **Added Process Types**
```c
typedef enum {
    UNIXCOMM_PROCESS_QM = 0,    // Queue Manager
    UNIXCOMM_PROCESS_SM = 1,    // Statistics Manager
    UNIXCOMM_PROCESS_DM = 2,    // Device Manager
    UNIXCOMM_PROCESS_CM = 3     // Configuration Manager
} unixcomm_process_t;
```

#### **Updated Configuration Structure**
```c
typedef struct {
    char socket_path[UNIXCOMM_MAX_SOCK_PATH];
    char socket_dir[UNIXCOMM_MAX_SOCK_PATH];
    unixcomm_process_t target_process;  // ✅ Target process for communication
    double timeout;
    int max_pending;
    size_t buffer_size;
    bool enable_compression;
    bool enable_checksum;
    bool enable_heartbeat;
    int heartbeat_interval;
    char log_prefix[32];
} unixcomm_config_t;
```

#### **New API Function**
```c
bool unixcomm_config_set_target_process(unixcomm_config_t *config, unixcomm_process_t process);
```

### **2. Optional pthread Support**

#### **Conditional Compilation**
```c
// Optional pthread support
#ifdef UNIXCOMM_HAVE_PTHREAD
#include <pthread.h>
#endif

// Thread safety (optional - only if pthread is available)
#ifdef UNIXCOMM_HAVE_PTHREAD
bool unixcomm_lock_handle(unixcomm_handle_t *handle);
bool unixcomm_unlock_handle(unixcomm_handle_t *handle);
#endif
```

#### **Updated Makefile**
```makefile
# Optional pthread support
ifneq ($(shell pkg-config --exists libpthread && echo "yes"),)
CFLAGS += -DUNIXCOMM_HAVE_PTHREAD
LDLIBS += -lpthread
endif
```

## 🚀 **Usage Examples**

### **1. QM Process Creating Server for SM**
```c
unixcomm_config_t config;
unixcomm_config_init(&config);

// Set target process to SM - auto-generates /tmp/aircnms/sm.sock
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_SM);
unixcomm_config_set_timeout(&config, 2.0);

unixcomm_handle_t server;
unixcomm_server_create(&server, &config);
```

### **2. SM Process Creating Client for QM**
```c
unixcomm_config_t config;
unixcomm_config_init(&config);

// Set target process to QM - auto-generates /tmp/aircnms/qm.sock
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
unixcomm_config_set_timeout(&config, 2.0);

unixcomm_handle_t client;
unixcomm_client_create(&client, &config);
unixcomm_connect(&client);
```

### **3. DM Process Creating Client for QM**
```c
unixcomm_config_t config;
unixcomm_config_init(&config);

// Set target process to QM - auto-generates /tmp/aircnms/qm.sock
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
unixcomm_config_set_timeout(&config, 2.0);

unixcomm_handle_t client;
unixcomm_client_create(&client, &config);
unixcomm_connect(&client);
```

### **4. CM Process Creating Client for QM**
```c
unixcomm_config_t config;
unixcomm_config_init(&config);

// Set target process to QM - auto-generates /tmp/aircnms/qm.sock
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
unixcomm_config_set_timeout(&config, 2.0);

unixcomm_handle_t client;
unixcomm_client_create(&client, &config);
unixcomm_connect(&client);
```

## 📋 **Auto-Generated Socket Paths**

| Process | Socket Path |
|---------|-------------|
| **QM** | `/tmp/aircnms/qm.sock` |
| **SM** | `/tmp/aircnms/sm.sock` |
| **DM** | `/tmp/aircnms/dm.sock` |
| **CM** | `/tmp/aircnms/cm.sock` |

## 🔧 **Implementation Details**

### **1. Process Socket Name Mapping**
```c
static const char *unixcomm_get_process_socket_name(unixcomm_process_t process) {
    switch (process) {
        case UNIXCOMM_PROCESS_QM: return "qm";
        case UNIXCOMM_PROCESS_SM: return "sm";
        case UNIXCOMM_PROCESS_DM: return "dm";
        case UNIXCOMM_PROCESS_CM: return "cm";
        default: return NULL;
    }
}
```

### **2. Auto-Generated Socket Path**
```c
bool unixcomm_config_set_target_process(unixcomm_config_t *config, unixcomm_process_t process) {
    if (!config) return false;
    
    config->target_process = process;
    
    // Auto-generate socket path based on process
    const char *process_name = unixcomm_get_process_socket_name(process);
    if (process_name) {
        snprintf(config->socket_path, UNIXCOMM_MAX_SOCK_PATH, "%s/%s.sock", 
                config->socket_dir, process_name);
    }
    
    return true;
}
```

### **3. Optional pthread Support**
```c
// Global structure with optional pthread
typedef struct {
    bool initialized;
    unixcomm_global_config_t config;
#ifdef UNIXCOMM_HAVE_PTHREAD
    pthread_mutex_t global_mutex;
#endif
} unixcomm_global_t;

// Initialization with optional pthread
bool unixcomm_init(const unixcomm_global_config_t *global_config) {
    // ... other initialization code ...
    
#ifdef UNIXCOMM_HAVE_PTHREAD
    if (pthread_mutex_init(&g_unixcomm.global_mutex, NULL) != 0) {
        return false;
    }
#endif
    
    g_unixcomm.initialized = true;
    return true;
}
```

## ✅ **Benefits**

### **1. Process-Specific Communication**
- **Clear Intent**: Explicitly specify which process to communicate with
- **Auto-Generated Paths**: No need to manually construct socket paths
- **Consistent Naming**: Standardized socket path naming convention
- **Easy Migration**: Simple API for existing code

### **2. Optional pthread Dependency**
- **No Required Dependencies**: Library works without pthread
- **Optional Threading**: pthread support when available
- **Conditional Compilation**: Clean separation of threading code
- **Flexible Deployment**: Works in environments without pthread

### **3. Simplified Usage**
```c
// OLD: Manual socket path construction
unixcomm_config_set_socket_path(&config, "/tmp/aircnms/qm.sock");

// NEW: Process-specific API
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
```

## 🎯 **Migration Guide**

### **For QM Process**
```c
// Create server for SM communication
unixcomm_config_t config;
unixcomm_config_init(&config);
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_SM);
unixcomm_server_create(&server, &config);
```

### **For SM Process**
```c
// Create client for QM communication
unixcomm_config_t config;
unixcomm_config_init(&config);
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
unixcomm_client_create(&client, &config);
unixcomm_connect(&client);
```

### **For DM Process**
```c
// Create client for QM communication
unixcomm_config_t config;
unixcomm_config_init(&config);
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
unixcomm_client_create(&client, &config);
unixcomm_connect(&client);
```

### **For CM Process**
```c
// Create client for QM communication
unixcomm_config_t config;
unixcomm_config_init(&config);
unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
unixcomm_client_create(&client, &config);
unixcomm_connect(&client);
```

## 📊 **Summary**

The UnixComm library now provides:

1. **Process-Specific API**: Easy specification of target process
2. **Auto-Generated Paths**: Consistent socket path naming
3. **Optional pthread**: No required dependencies
4. **Flexible Deployment**: Works in various environments
5. **Easy Migration**: Simple API for existing code

This addresses both user concerns:
- ✅ **Common flag for socket path**: `unixcomm_config_set_target_process()`
- ✅ **Optional pthread**: Conditional compilation with `UNIXCOMM_HAVE_PTHREAD`
