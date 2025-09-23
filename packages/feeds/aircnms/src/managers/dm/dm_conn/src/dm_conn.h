#ifndef DM_CONN_H_INCLUDED
#define DM_CONN_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

// request

#define DM_REQUEST_TAG "QREQ"
#define DM_REQUEST_VER 2
#define DM_CONN_DEFAULT_TIMEOUT 2.0 // timeout in seconds (float)

enum dm_req_cmd
{
    DM_CMD_STATUS = 1,
    DM_CMD_SEND   = 2,
};

// flag: skip sending response
#define DM_REQ_FLAG_NO_RESPONSE (1<<0)

// flag: send directly to mqtt broker, bypassing the queue and interval
#define DM_REQ_FLAG_SEND_DIRECT (1<<1)

typedef enum dm_req_compress
{
    DM_REQ_COMPRESS_IF_CFG  = 0, // enabled by ovsdb mqtt conf
    DM_REQ_COMPRESS_DISABLE = 1, // disable
    DM_REQ_COMPRESS_FORCE   = 2, // always compress
} dm_compress_t;

// message data type
typedef enum dm_req_data_type
{
    DM_DATA_RAW = 0,
    DM_DATA_TEXT,
    DM_DATA_STATS,
    DM_DATA_LOG,
	DM_DATA_INI,
	DM_DATA_CONF,
	DM_DATA_CMD,
	DM_DATA_ACL,
} dm_data_type_t;

typedef struct dm_request
{
    char tag[4];
    uint32_t ver;
    uint32_t seq;
    uint32_t cmd;
    uint32_t flags;
    char sender[16]; // prog name

    uint8_t set_qos; // if 1 use qos_val instead of ovsdb cfg
    uint8_t qos_val;
    uint8_t compress;
    uint8_t data_type;

    uint32_t interval;
    uint32_t topic_len;
    uint32_t data_size;
    uint32_t reserved;
} dm_request_t;

// response

#define DM_RESPONSE_TAG "RESP"
#define DM_RESPONSE_VER 1

enum dm_response_type
{
    DM_RESPONSE_ERROR    = 0, // error response
    DM_RESPONSE_STATUS   = 1, // status response
    DM_RESPONSE_RECEIVED = 2, // message received confirmation
    DM_RESPONSE_IGNORED  = 3, // response ignored
};

// error type
enum dm_res_error
{
    DM_ERROR_NONE        = 0,   // no error
    DM_ERROR_GENERAL     = 100, // general error
    DM_ERROR_CONNECT     = 101, // error connecting to DM
    DM_ERROR_INVALID     = 102, // invalid response
    DM_ERROR_QUEUE       = 103, // error enqueuing message
    DM_ERROR_SEND        = 104, // error sending to mqtt (for immediate flag)
};

// status of connection from DM to the mqtt server
enum dm_res_conn_status
{
    DM_CONN_STATUS_NO_CONF      = 200,
    DM_CONN_STATUS_DISCONNECTED = 201,
    DM_CONN_STATUS_CONNECTED    = 202,
};

typedef struct dm_response
{
    char tag[4];
    uint32_t ver;
    uint32_t seq;
    uint32_t response;
    uint32_t error;
    uint32_t flags;
    uint32_t conn_status;
    // stats
    uint32_t qlen;  // queue length - number of messages
    uint32_t qsize; // queue size - bytes
    uint32_t qdrop; // num queued messages dropped due to queue full
    uint32_t log_size; // log buffer size
    uint32_t log_drop; // log dropped lines
} dm_response_t;

char *dm_data_type_str(enum dm_req_data_type type);
char *dm_response_str(enum dm_response_type x);
char *dm_error_str(enum dm_res_error x);
char *dm_conn_status_str(enum dm_res_conn_status x);

bool dm_conn_accept(int listen_fd, int *accept_fd);
bool dm_conn_server(int *pfd);
bool dm_conn_client(int *pfd);

/**
 * @brief Set the dm_conn default timeout
 *
 * This overrides the default timeout of DM_CONN_DEFAULT_TIMEOUT
 * If set to 0 then never timeout
 *
 * @param timeout timeout in seconds (float)
 */
void dm_conn_set_default_timeout(double timeout);

/**
 * @brief Set the dm_conn timeout for a specific session
 *
 * This overrides the dm_conn timeout for a specific session
 * If set to 0 then never timeout
 *
 * @param fd dm_conn session
 * @param timeout timeout in seconds (float)
 */
bool dm_conn_set_fd_timeout(int fd, double timeout);


void dm_req_init(dm_request_t *req);
bool dm_req_valid(dm_request_t *req);
bool dm_conn_write_req(int fd, dm_request_t *req, char *topic, void *data, int data_size);
bool dm_conn_read_req(int fd, dm_request_t *req, char **topic, void **data);
bool dm_conn_parse_req(void *buf, int buf_size, dm_request_t *req, char **topic, void **data, bool *complete);

void dm_res_init(dm_response_t *res, dm_request_t *req);
bool dm_res_valid(dm_response_t *res);
bool dm_conn_write_res(int fd, dm_response_t *res);
bool dm_conn_read_res(int fd, dm_response_t *res);
bool dm_conn_open_fd(int *fd, dm_response_t *res);
bool dm_conn_send_fd(int fd, dm_request_t *req, char *topic, void *data, int data_size, dm_response_t *res);

// simple api

bool dm_conn_get_status(dm_response_t *res);
bool dm_conn_send_req(dm_request_t *req, char *topic, void *data, int data_size, dm_response_t *res);
bool dm_conn_send_custom(
        dm_data_type_t data_type,
        dm_compress_t compress,
        uint32_t flags,
        char *topic,
        void *data,
        int data_size,
        dm_response_t *res);
bool dm_conn_send_raw(char *topic, void *data, int data_size, dm_response_t *res);
bool dm_conn_send_direct(dm_compress_t compress, char *topic, void *data, int data_size, dm_response_t *res);
bool dm_conn_send_stats(void *data, int data_size, dm_response_t *res);
bool dm_conn_send_topic_stats(void *data, int data_size, dm_response_t *res, char *topic);

// streaming api

typedef struct
{
    bool init;
    int  fd;
    dm_response_t res;
} dm_conn_t;

bool dm_conn_open(dm_conn_t *qc);
bool dm_conn_close(dm_conn_t *qc);
bool dm_conn_send_stream(dm_conn_t *qc, dm_request_t *req, char *topic,
        void *data, int data_size, dm_response_t *res);
bool dm_conn_send_log(char *msg, dm_response_t *res);
void dm_conn_log_close();

#endif /* DM_CONN_H_INCLUDED */
