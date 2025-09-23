#ifndef CM_CONN_H_INCLUDED
#define CM_CONN_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

// request

#define CM_REQUEST_TAG "QREQ"
#define CM_REQUEST_VER 2
#define CM_CONN_DEFAULT_TIMEOUT 2.0 // timeout in seconds (float)

enum cm_req_cmd
{
    CM_CMD_STATUS = 1,
    CM_CMD_SEND   = 2,
};

// flag: skip sending response
#define CM_REQ_FLAG_NO_RESPONSE (1<<0)

// flag: send directly to mqtt broker, bypassing the queue and interval
#define CM_REQ_FLAG_SEND_DIRECT (1<<1)

typedef enum cm_req_compress
{
    CM_REQ_COMPRESS_IF_CFG  = 0, // enabled by ovsdb mqtt conf
    CM_REQ_COMPRESS_DISABLE = 1, // disable
    CM_REQ_COMPRESS_FORCE   = 2, // always compress
} cm_compress_t;

// message data type
typedef enum cm_req_data_type
{
    CM_DATA_RAW = 0,
    CM_DATA_TEXT,
    CM_DATA_STATS,
    CM_DATA_LOG,
    CM_DATA_INI,
    CM_DATA_CONF,
    CM_DATA_CMD,
    CM_DATA_ACL,
    CM_DATA_RL
} cm_data_type_t;

typedef struct cm_request
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
} cm_request_t;

// response

#define CM_RESPONSE_TAG "RESP"
#define CM_RESPONSE_VER 1

enum cm_response_type
{
    CM_RESPONSE_ERROR    = 0, // error response
    CM_RESPONSE_STATUS   = 1, // status response
    CM_RESPONSE_RECEIVED = 2, // message received confirmation
    CM_RESPONSE_IGNORED  = 3, // response ignored
};

// error type
enum cm_res_error
{
    CM_ERROR_NONE        = 0,   // no error
    CM_ERROR_GENERAL     = 100, // general error
    CM_ERROR_CONNECT     = 101, // error connecting to CM
    CM_ERROR_INVALID     = 102, // invalid response
    CM_ERROR_QUEUE       = 103, // error enqueuing message
    CM_ERROR_SEND        = 104, // error sending to mqtt (for immediate flag)
};

// status of connection from CM to the mqtt server
enum cm_res_conn_status
{
    CM_CONN_STATUS_NO_CONF      = 200,
    CM_CONN_STATUS_DISCONNECTED = 201,
    CM_CONN_STATUS_CONNECTED    = 202,
};

typedef struct cm_response
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
} cm_response_t;

char *cm_data_type_str(enum cm_req_data_type type);
char *cm_response_str(enum cm_response_type x);
char *cm_error_str(enum cm_res_error x);
char *cm_conn_status_str(enum cm_res_conn_status x);

bool cm_conn_accept(int listen_fd, int *accept_fd);
bool cm_conn_server(int *pfd);
bool cm_conn_client(int *pfd);

/**
 * @brief Set the cm_conn default timeout
 *
 * This overrides the default timeout of CM_CONN_DEFAULT_TIMEOUT
 * If set to 0 then never timeout
 *
 * @param timeout timeout in seconds (float)
 */
void cm_conn_set_default_timeout(double timeout);

/**
 * @brief Set the cm_conn timeout for a specific session
 *
 * This overrides the cm_conn timeout for a specific session
 * If set to 0 then never timeout
 *
 * @param fd cm_conn session
 * @param timeout timeout in seconds (float)
 */
bool cm_conn_set_fd_timeout(int fd, double timeout);


void cm_req_init(cm_request_t *req);
bool cm_req_valid(cm_request_t *req);
bool cm_conn_write_req(int fd, cm_request_t *req, char *topic, void *data, int data_size);
bool cm_conn_read_req(int fd, cm_request_t *req, char **topic, void **data);
bool cm_conn_parse_req(void *buf, int buf_size, cm_request_t *req, char **topic, void **data, bool *complete);

void cm_res_init(cm_response_t *res, cm_request_t *req);
bool cm_res_valid(cm_response_t *res);
bool cm_conn_write_res(int fd, cm_response_t *res);
bool cm_conn_read_res(int fd, cm_response_t *res);
bool cm_conn_open_fd(int *fd, cm_response_t *res);
bool cm_conn_send_fd(int fd, cm_request_t *req, char *topic, void *data, int data_size, cm_response_t *res);

// simple api

bool cm_conn_get_status(cm_response_t *res);
bool cm_conn_send_req(cm_request_t *req, char *topic, void *data, int data_size, cm_response_t *res);
bool cm_conn_send_custom(
        cm_data_type_t data_type,
        cm_compress_t compress,
        uint32_t flags,
        char *topic,
        void *data,
        int data_size,
        cm_response_t *res);
bool cm_conn_send_raw(char *topic, void *data, int data_size, cm_response_t *res);
bool cm_conn_send_direct(cm_compress_t compress, char *topic, void *data, int data_size, cm_response_t *res);
bool cm_conn_send_stats(void *data, int data_size, cm_response_t *res);
bool cm_conn_send_topic_stats(void *data, int data_size, cm_response_t *res, char *topic);

// streaming api

typedef struct
{
    bool init;
    int  fd;
    cm_response_t res;
} cm_conn_t;

bool cm_conn_open(cm_conn_t *qc);
bool cm_conn_close(cm_conn_t *qc);
bool cm_conn_send_stream(cm_conn_t *qc, cm_request_t *req, char *topic,
        void *data, int data_size, cm_response_t *res);
bool cm_conn_send_log(char *msg, cm_response_t *res);
void cm_conn_log_close();

#endif /* CM_CONN_H_INCLUDED */
