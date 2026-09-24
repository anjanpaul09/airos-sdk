#ifndef CONFIG_H
#define CONFIG_H

#define MAX_STR_LEN 64     // Max length for string fields
#define MAX_DATA_LEN 10240   // Max length for data fields

// Device Configuration Structure
typedef struct {
    char fw_info[MAX_STR_LEN];    // Firmware information
    char hw_version[MAX_STR_LEN]; // Hardware version
    char mgmt_ip[MAX_STR_LEN];    // Management IP address
    char egress_ip[MAX_STR_LEN];  // Egress IP address
} device_conf_t;

// Event Type Enumeration
typedef enum {
    EVENT_TYPE_UPGRADE = 1,
    EVENT_TYPE_ALARM = 2,
    EVENT_TYPE_CMD = 3,
    EVENT_TYPE_ALERT = 4
} event_type_t;

// Event Status Enumeration
typedef enum {
    EVENT_STATUS_DOWNLOADED = 1,
    EVENT_STATUS_UPGRADING = 2,
    EVENT_STATUS_UPGRADED = 3,
    EVENT_STATUS_FAILED = 4,
    EVENT_STATUS_REBOOT = 5
} event_status_t;

typedef enum {
    ALARM_TYPE_CRITICAL = 1,
    ALARM_TYPE_MAJOR = 2,
    ALARM_TYPE_WARNING = 3
} alarm_subtype_t;

typedef enum {
    ALERT_TYPE_INTERFACE = 1,
    ALERT_TYPE_SYSTEM = 2
} alert_subtype_t;

// Event Message Structure
typedef struct {
    event_type_t type;        // Event type
    event_status_t status;    // Event status
    alarm_subtype_t alarm_t;
    alert_subtype_t alert_t;
    char data[MAX_DATA_LEN];  // Additional data
    char reason[MAX_DATA_LEN];// Reason for event
    char cloud_id[MAX_DATA_LEN]; // Cloud ID
} event_msg_t;

// Alarm Message Structure
typedef struct {
    char type[MAX_STR_LEN];   // Alarm type
    char reason[MAX_STR_LEN]; // Reason for alarm
} alarm_msg_t;

#endif // CONFIG_H

