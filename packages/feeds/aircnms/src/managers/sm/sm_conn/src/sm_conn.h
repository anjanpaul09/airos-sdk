#ifndef SM_CONN_H_INCLUDED
#define SM_CONN_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

// request

#define SM_REQUEST_TAG "QREQ"
#define SM_REQUEST_VER 2
#define SM_CONN_DEFAULT_TIMEOUT 2.0 // timeout in seconds (float)

enum sm_req_cmd
{
    SM_CMD_STATUS = 1,
    SM_CMD_SEND   = 2,
};

// flag: skip sending response
#define SM_REQ_FLAG_NO_RESPONSE (1<<0)

// flag: send directly to mqtt broker, bypassing the queue and interval
#define SM_REQ_FLAG_SEND_DIRECT (1<<1)

typedef enum sm_req_compress
{
    SM_REQ_COMPRESS_IF_CFG  = 0, // enabled by ovsdb mqtt conf
    SM_REQ_COMPRESS_DISABLE = 1, // disable
    SM_REQ_COMPRESS_FORCE   = 2, // always compress
} sm_compress_t;

// message data type
typedef enum sm_req_data_type
{
    SM_DATA_RAW = 0,
    SM_DATA_TEXT,
    SM_DATA_STATS,
    SM_DATA_LOG,
    SM_DATA_CMD,
} sm_data_type_t;

typedef struct sm_request
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
} sm_request_t;

// response

#define SM_RESPONSE_TAG "RESP"
#define SM_RESPONSE_VER 1

enum sm_response_type
{
    SM_RESPONSE_ERROR    = 0, // error response
    SM_RESPONSE_STATUS   = 1, // status response
    SM_RESPONSE_RECEIVED = 2, // message received confirmation
    SM_RESPONSE_IGNORED  = 3, // response ignored
};

// error type
enum sm_res_error
{
    SM_ERROR_NONE        = 0,   // no error
    SM_ERROR_GENERAL     = 100, // general error
    SM_ERROR_CONNECT     = 101, // error connecting to SM
    SM_ERROR_INVALID     = 102, // invalid response
    SM_ERROR_QUEUE       = 103, // error enqueuing message
    SM_ERROR_SEND        = 104, // error sending to mqtt (for immediate flag)
};

// status of connection from SM to the mqtt server
enum sm_res_conn_status
{
    SM_CONN_STATUS_NO_CONF      = 200,
    SM_CONN_STATUS_DISCONNECTED = 201,
    SM_CONN_STATUS_CONNECTED    = 202,
};

typedef struct sm_response
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
} sm_response_t;

char *sm_data_type_str(enum sm_req_data_type type);
char *sm_response_str(enum sm_response_type x);
char *sm_error_str(enum sm_res_error x);
char *sm_conn_status_str(enum sm_res_conn_status x);

bool sm_conn_accept(int listen_fd, int *accept_fd);
bool sm_conn_server(int *pfd);
bool sm_conn_client(int *pfd);

/**
 * @brief Set the sm_conn default timeout
 *
 * This overrides the default timeout of SM_CONN_DEFAULT_TIMEOUT
 * If set to 0 then never timeout
 *
 * @param timeout timeout in seconds (float)
 */
void sm_conn_set_default_timeout(double timeout);

/**
 * @brief Set the sm_conn timeout for a specific session
 *
 * This overrides the sm_conn timeout for a specific session
 * If set to 0 then never timeout
 *
 * @param fd sm_conn session
 * @param timeout timeout in seconds (float)
 */
bool sm_conn_set_fd_timeout(int fd, double timeout);


void sm_req_init(sm_request_t *req);
bool sm_req_valid(sm_request_t *req);
bool sm_conn_write_req(int fd, sm_request_t *req, char *topic, void *data, int data_size);
bool sm_conn_read_req(int fd, sm_request_t *req, char **topic, void **data);
bool sm_conn_parse_req(void *buf, int buf_size, sm_request_t *req, char **topic, void **data, bool *complete);

void sm_res_init(sm_response_t *res, sm_request_t *req);
bool sm_res_valid(sm_response_t *res);
bool sm_conn_write_res(int fd, sm_response_t *res);
bool sm_conn_read_res(int fd, sm_response_t *res);
bool sm_conn_open_fd(int *fd, sm_response_t *res);
bool sm_conn_send_fd(int fd, sm_request_t *req, char *topic, void *data, int data_size, sm_response_t *res);

// simple api

bool sm_conn_get_status(sm_response_t *res);
bool sm_conn_send_req(sm_request_t *req, char *topic, void *data, int data_size, sm_response_t *res);
bool sm_conn_send_custom(
        sm_data_type_t data_type,
        sm_compress_t compress,
        uint32_t flags,
        char *topic,
        void *data,
        int data_size,
        sm_response_t *res);
bool sm_conn_send_raw(char *topic, void *data, int data_size, sm_response_t *res);
bool sm_conn_send_direct(sm_compress_t compress, char *topic, void *data, int data_size, sm_response_t *res);
bool sm_conn_send_stats(void *data, int data_size, sm_response_t *res);
bool sm_conn_send_topic_stats(void *data, int data_size, sm_response_t *res, char *topic);

// streaming api

typedef struct
{
    bool init;
    int  fd;
    sm_response_t res;
} sm_conn_t;

bool sm_conn_open(sm_conn_t *qc);
bool sm_conn_close(sm_conn_t *qc);
bool sm_conn_send_stream(sm_conn_t *qc, sm_request_t *req, char *topic,
        void *data, int data_size, sm_response_t *res);
bool sm_conn_send_log(char *msg, sm_response_t *res);
void sm_conn_log_close();

#endif /* SM_CONN_H_INCLUDED */
