#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <poll.h>

#include "log.h"
#include "os.h"
#include "os_time.h"
#include "util.h"
#include "memutil.h"
#include "cm_conn.h"

#define CM_SOCK_DIR "/tmp/aircnms/"
#define CM_SOCK_FILENAME CM_SOCK_DIR"cm.sock"
#define CM_SOCK_MAX_PENDING 10
#define CM_COMPACT_SEND_SIZE (64*1024)

static double cm_conn_default_timeout = CM_CONN_DEFAULT_TIMEOUT;

extern const char *log_get_name();

// server
bool cm_conn_server(int *pfd)
{
    struct sockaddr_un addr;
    char *path = CM_SOCK_FILENAME;
    int fd;

    mkdir(CM_SOCK_DIR, 0755);
    errno = 0; // ignore dir exist error

    *pfd = -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG(ERR, "socket");
        return false;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*path == '\0') {
        // hidden
        *addr.sun_path = '\0';
        strscpy(addr.sun_path+1, path+1, sizeof(addr.sun_path)-1);
    } else {
        STRSCPY(addr.sun_path, path);
        unlink(path);
    }
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG(ERR, "bind");
        close(fd);
        return false;
    }
    if (listen(fd, CM_SOCK_MAX_PENDING) < 0) {
        LOG(ERR, "listen");
        close(fd);
        return false;
    }
    *pfd = fd;
    LOG(TRACE, "%s %s", __FUNCTION__, path);

    return true;
}

bool cm_conn_accept(int listen_fd, int *accept_fd)
{
    *accept_fd = accept(listen_fd, NULL, NULL);
    if (*accept_fd < 0) {
        LOG(ERR, "%s: accept %d", __FUNCTION__, errno);
        return false;
    }
    return true;
}

// client

void cm_conn_set_default_timeout(double timeout)
{
    cm_conn_default_timeout = timeout;
}

bool cm_conn_set_fd_timeout(int fd, double timeout)
{
    int ret;
    struct timeval tv;
    tv.tv_sec = (int)timeout;
    tv.tv_usec = (int)((timeout - (int)timeout) * 1000000.0);
    ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    if (ret != 0) goto error;
    ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
    if (ret != 0) goto error;
    return true;
error:
    LOGE("setsockopt(%d,%f) = %d %d", fd, timeout, ret, errno);
    return false;
}


bool cm_conn_client(int *pfd)
{
    struct sockaddr_un addr;
    char *path = CM_SOCK_FILENAME;
    int fd;
    mkdir(CM_SOCK_DIR, 0755);

    *pfd = -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( fd < 0) {
        LOG(ERR, "socket");
        return false;
    }

    // set timeout; if 0 then never timeout
    if (cm_conn_default_timeout > 0) {
        if (!cm_conn_set_fd_timeout(fd, cm_conn_default_timeout)) {
            close(fd);
            return false;
        }
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*path == '\0') {
        // hidden
        *addr.sun_path = '\0';
        strscpy(addr.sun_path+1, path+1, sizeof(addr.sun_path)-1);
    } else {
        STRSCPY(addr.sun_path, path);
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        LOG(ERR, "connect %s", path);
        close(fd);
        return false;
    }
    LOG(TRACE, "%s %s", __FUNCTION__, path);

    *pfd = fd;

    return true;
}

// request

void cm_req_init(cm_request_t *req)
{
    static int seq = 0;
    if (!seq) {
        seq = time_monotonic();
    }
    memset(req, 0, sizeof(*req));
    memcpy(req->tag, CM_REQUEST_TAG, sizeof(req->tag));
    STRSCPY(req->sender, log_get_name());
    req->ver = CM_REQUEST_VER;
    req->seq = seq;
    seq++;
}

bool cm_req_valid(cm_request_t *req)
{
    return (memcmp(req->tag, CM_REQUEST_TAG, sizeof(req->tag)) == 0)
            && (req->ver == CM_REQUEST_VER);
}

bool cm_conn_write_req(int fd, cm_request_t *req, char *topic, void *data, int data_size)
{
    int ret;
    int size;
    int total = 0;

    if (topic && *topic) {
        req->topic_len = strlen(topic) + 1;
    } else {
        req->topic_len = 0;
    }

    req->data_size = data_size;

    total = sizeof(*req) + req->topic_len + req->data_size;
    if (total <= CM_COMPACT_SEND_SIZE)
    {
        // merge small messages (<64k) into a single send
        void *msgbuf = MALLOC(total);
        void *p = msgbuf;
        memcpy(p, req, sizeof(*req));
        p += sizeof(*req);
        if (req->topic_len) {
            memcpy(p, topic, req->topic_len);
            p += req->topic_len;
        }
        if (data_size) {
            memcpy(p, data, data_size);
            p += data_size;
        }
        size = total;
        ret = send(fd, msgbuf, total, MSG_NOSIGNAL);
        FREE(msgbuf);
        if (ret != total) goto write_err;
    } else {
        size = sizeof(*req);
        ret = send(fd, req, size, MSG_NOSIGNAL);
        if (ret != size) goto write_err;
        total += size;

        size = req->topic_len;
        if (size) {
            ret = send(fd, topic, size, MSG_NOSIGNAL);
            if (ret != size) goto write_err;
        }
        total += size;

        size = req->data_size;
        if (size) {
            ret = send(fd, data, size, MSG_NOSIGNAL);
            if (ret != size) goto write_err;
        }
        total += size;
    }

    LOG(TRACE, "%s(%d t:%s ds:%d): b:%d", __FUNCTION__,
            req->cmd, topic ? topic : "null", data_size, total);

    return true;

write_err:
    LOG(ERR, "%s: write error %d / %d / %d %s", __FUNCTION__, size, ret, errno, strerror(errno));
    return false;

}

bool cm_conn_read_req(int fd, cm_request_t *req, char **topic, void **data)
{
    int ret;
    int size;
    int total = 0;

    *topic = NULL;
    *data = NULL;

    // read req
    size = sizeof(*req);
    ret = read(fd, req, size);
    if (ret != size) goto read_err;
    total += size;

    // read topic
    size = req->topic_len;
    if (size) {
        *topic = CALLOC(size + 1, 1);
        ret = read(fd, *topic, size);
        if (ret != size) goto read_err;
    }
    total += size;

    // read buf
    size = req->data_size;
    if (size) {
        *data = MALLOC(size);
        ret = read(fd, *data, size);
        if (ret != size) goto read_err;
    }
    total += size;

    LOG(TRACE, "%s: t:%s ds:%d b:%d", __FUNCTION__, *topic, size, total);

    return true;

//alloc_err:
  //  LOG(ERR, "%s: alloc %d", __FUNCTION__, size);
    //goto error;
read_err:
    LOG(ERR, "%s: read error %d / %d / %d %s", __FUNCTION__, size, ret, errno, strerror(errno));
error:
    FREE(*topic);
    FREE(*data);
    *topic = NULL;
    *data = NULL;
    return false;
}

// for async call
// complete is set to true when buf has enough data for one request
bool cm_conn_parse_req(void *buf, int buf_size, cm_request_t *req, char **topic, void **data, bool *complete)
{
    int size;
    int total = 0;

    *topic = NULL;
    *data = NULL;
    *complete = false;

    // read req
    size = sizeof(*req);
    if (buf_size < size) {
        LOG(TRACE, "%s: incomplete %d/%d req", __FUNCTION__, buf_size, size);
        return true;
    }
    memcpy(req, buf, size);

    total = size + req->topic_len + req->data_size;
    if (buf_size < total) {
        LOG(TRACE, "%s: incomplete %d/%d total", __FUNCTION__, buf_size, total);
        return true;
    }

    // read topic
    size = req->topic_len;
    if (size) {
        *topic = CALLOC(size + 1, 1);
        //ret = read(fd, *topic, size);
        memcpy(*topic, buf + sizeof(*req), size);
    }

    // read buf
    size = req->data_size;
    if (size) {
        *data = MALLOC(size);
        //ret = read(fd, *data, size);
        memcpy(*data, buf + sizeof(*req) + req->topic_len, size);
    }

    LOG(TRACE, "%s: complete from:%s c:%d to:%s dt:%d ds:%d b:%d", __FUNCTION__,
            req->sender, req->cmd, *topic ? *topic : "null", req->data_type, size, total);
    *complete = true;
    return true;

error:
    LOG(ERR, "%s: alloc %d", __FUNCTION__, size);
    FREE(*topic);
    FREE(*data);
    *topic = NULL;
    *data = NULL;
    return false;
}


// response

void cm_res_init(cm_response_t *res, cm_request_t *req)
{
    memset(res, 0, sizeof(*res));
    memcpy(res->tag, CM_RESPONSE_TAG, sizeof(res->tag));
    res->ver = CM_RESPONSE_VER;
    res->seq = req->seq;
    switch (req->cmd) {
        case CM_CMD_STATUS:
            res->response = CM_RESPONSE_STATUS;
            break;
        case CM_CMD_SEND:
            res->response = CM_RESPONSE_RECEIVED;
            break;
        default:
            break;
    }
}

bool cm_res_valid(cm_response_t *res)
{
    return (memcmp(res->tag, CM_RESPONSE_TAG, sizeof(res->tag)) == 0)
            && (res->ver == CM_RESPONSE_VER);
}

bool cm_conn_write_res(int fd, cm_response_t *res)
{
    int ret;
    int size = sizeof(*res);
    ret = write(fd, res, size);
    if (ret != size) {
        LOG(ERR, "write");
        return false;
    }
    LOG(TRACE, "%s: b:%d", __FUNCTION__, size);
    return true;
}

bool cm_conn_read_res(int fd, cm_response_t *res)
{
    int ret;
    int size;

    size = sizeof(*res);
    errno = 0;
    ret = read(fd, res, size);
    if (ret != size) {
        LOG(ERR, "%s: read error %d / %d / %d %s", __FUNCTION__, size, ret, errno, strerror(errno));
        res->response = CM_RESPONSE_ERROR;
        res->error = CM_ERROR_CONNECT;
        return false;
    }
    if (!cm_res_valid(res)) {
        LOG(ERR, "%s: invalid response %.4s %d", __FUNCTION__, res->tag, res->ver);
        res->response = CM_RESPONSE_ERROR;
        res->error = CM_ERROR_INVALID;
        return false;
    }
    LOG(TRACE, "%s: b:%d", __FUNCTION__, size);
    return true;
}

// send

// res can be NULL
bool cm_conn_get_status(cm_response_t *res)
{
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_STATUS;
    return cm_conn_send_req(&req, NULL, NULL, 0, res);
}

char *cm_data_type_str(enum cm_req_data_type type)
{
    switch (type) {
        case CM_DATA_RAW:   return "raw";
        case CM_DATA_TEXT:  return "bs";
        case CM_DATA_STATS: return "stats";
        case CM_DATA_LOG:   return "log";
        default:            return "unk";  //Ankit
    }
    return "unk";
}

char *cm_response_str(enum cm_response_type x)
{
    switch (x) {
        case CM_RESPONSE_ERROR:    return "error";
        case CM_RESPONSE_STATUS:   return "status";
        case CM_RESPONSE_RECEIVED: return "ok";
        case CM_RESPONSE_IGNORED:  return "ignored";
    }
    return "unk";
}

char *cm_error_str(enum cm_res_error x)
{
    switch (x) {
        case CM_ERROR_NONE:    return "";
        case CM_ERROR_GENERAL: return "error";
        case CM_ERROR_CONNECT: return "connect";
        case CM_ERROR_INVALID: return "invalid";
        case CM_ERROR_QUEUE:   return "queue";
        case CM_ERROR_SEND:    return "send";
    }
    return "unk";
}

char *cm_conn_status_str(enum cm_res_conn_status x)
{
    switch (x) {
        case CM_CONN_STATUS_NO_CONF:      return "no-conf";
        case CM_CONN_STATUS_DISCONNECTED: return "diconnected";
        case CM_CONN_STATUS_CONNECTED:    return "connected";
    }
    return "unk";
}

bool cm_conn_open_fd(int *fd, cm_response_t *res)
{
    cm_response_t res1;

    if (!res) res = &res1;
    MEMZERO(*res);
    if (!cm_conn_client(fd)) {
        res->error = CM_ERROR_CONNECT;
        LOG(ERROR, "connecting to cm");
        return false;
    }
    return true;
}

bool cm_conn_send_fd(int fd, cm_request_t *req, char *topic, void *data, int data_size, cm_response_t *res)
{
    bool result = false;
    cm_response_t res1;
    int ll = LOG_SEVERITY_TRACE;

    if (!req) return false;
    if (!res) res = &res1;
    MEMZERO(*res);

    if (!cm_req_valid(req)) {
        LOG(ERR, "%s: invalid req", __FUNCTION__);
        res->error = CM_ERROR_GENERAL;
        goto out;
    }
    if (fd < 0) {
        res->error = CM_ERROR_CONNECT;
        goto out;
    }
    if (!cm_conn_write_req(fd, req, topic, data, data_size)) {
        res->error = CM_ERROR_CONNECT;
        goto out;
    }
    if (!(req->flags & CM_REQ_FLAG_NO_RESPONSE)) {
        if (!cm_conn_read_res(fd, res)) {
            goto out;
        }
    } else {
        res->response = CM_RESPONSE_IGNORED;
    }
    result = true;
out:
    if (!result || res->response == CM_RESPONSE_ERROR) {
        // on either error set both return value and response type to error
        result = false;
        res->response = CM_RESPONSE_ERROR;
        if (!res->error) res->error = CM_ERROR_GENERAL;
        if (req->cmd != CM_CMD_STATUS) {
            // elevate log to error unless cmd is status request
            ll = LOG_SEVERITY_ERROR;
        }
    }

    LOG_SEVERITY(ll, "%s: req c:%d dt:%d ds:%d to:%s result:%d response:%d err:%d", __FUNCTION__,
            req->cmd, req->data_type, req->data_size, topic ? topic : "null",
            result, res->response, res->error);

    if (result && req->cmd == CM_CMD_SEND) {
        LOG(DEBUG, "Sent message to CM (size: %d type: %s)",
                data_size, cm_data_type_str(req->data_type));
    }

    return result;
}

// all params except req can be NULL
// returns true if message exchange succesfull and response is not of error type
// on error details can be found in res->error
bool cm_conn_send_req(cm_request_t *req, char *topic, void *data, int data_size, cm_response_t *res)
{
    int fd = -1;
    bool result = false;
    if (!cm_conn_open_fd(&fd, res)) {
        return false;
    }
    result = cm_conn_send_fd(fd, req, topic, data, data_size, res);
    close(fd);
    return result;
}

bool cm_conn_send_custom(
        cm_data_type_t data_type,
        cm_compress_t compress,
        uint32_t flags,
        char *topic,
        void *data,
        int data_size,
        cm_response_t *res)
{
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = data_type;
    req.compress = compress;
    req.flags = flags;
    return cm_conn_send_req(&req, topic, data, data_size, res);
}

bool cm_conn_send_raw(char *topic, void *data, int data_size, cm_response_t *res)
{
    return cm_conn_send_custom(
            CM_DATA_RAW, CM_REQ_COMPRESS_DISABLE, 0,
            topic, data, data_size, res);
}

bool cm_conn_send_direct(cm_compress_t compress, char *topic,
        void *data, int data_size, cm_response_t *res)
{
    return cm_conn_send_custom(
            CM_DATA_RAW, compress,
            CM_REQ_FLAG_SEND_DIRECT,
            topic, data, data_size, res);
}

bool cm_conn_send_topic_stats(void *data, int data_size, cm_response_t *res, char *topic)
{
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    if (strstr(topic, "config") != NULL) {
        req.data_type = CM_DATA_CONF;
    } else if (strstr(topic, "cmd") != NULL) {
        req.data_type = CM_DATA_CMD;
    } else if (strstr(topic, "bw_list") != NULL) {
        req.data_type = CM_DATA_ACL;
    } else if (strstr(topic, "rate_limit") != NULL) {
        req.data_type = CM_DATA_RL;
        } else {
        req.data_type = CM_DATA_STATS;
    }
    req.compress = CM_REQ_COMPRESS_IF_CFG;
    req.flags = CM_REQ_FLAG_NO_RESPONSE;
    return cm_conn_send_req(&req, NULL, data, data_size, res);
}

bool cm_conn_send_stats(void *data, int data_size, cm_response_t *res)
{
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = CM_DATA_STATS;
    req.compress = CM_REQ_COMPRESS_IF_CFG;
    return cm_conn_send_req(&req, NULL, data, data_size, res);
}

bool cm_conn_send_initial(void *data, int data_size, cm_response_t *res)
{
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = CM_DATA_INI;
    req.compress = CM_REQ_COMPRESS_IF_CFG;
    return cm_conn_send_req(&req, NULL, data, data_size, res);
}
// streaming api
// persistent connection for less overhead
// auto-reconnect on connection error

bool cm_conn_open(cm_conn_t *qc)
{
    MEMZERO(*qc);
    qc->init = true;
    qc->fd = -1;
    return cm_conn_open_fd(&qc->fd, &qc->res);
}

bool cm_conn_reopen(cm_conn_t *qc)
{
    if (!qc->init) return false;
    if (qc->fd > 0) close(qc->fd);
    qc->fd = -1;
    return cm_conn_open_fd(&qc->fd, &qc->res);
}

bool cm_conn_check_reconnect(cm_conn_t *qc)
{
    if (!qc->init) return false;
    if (qc->fd < 0) {
        // fd not open - reopen
        return cm_conn_reopen(qc);
    }
    // check if socket in good state
    int ret;
    struct pollfd pfd = {0,0,0};
    pfd.fd = qc->fd;
    pfd.events = 0;
    errno = 0;
    ret = poll(&pfd, 1, 0);
    if ((ret == 1) && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
        // socket in a bad state, reopen
        return cm_conn_reopen(qc);
    }
    return true;
}

bool cm_conn_close(cm_conn_t *qc)
{
    MEMZERO(qc->res);
    if (!qc->init) return false;
    if (qc->fd > 0) {
        close(qc->fd);
        qc->fd = -1;
    }
    qc->init = false;
    return true;
}

bool cm_conn_send_stream(cm_conn_t *qc, cm_request_t *req, char *topic, void *data, int data_size, cm_response_t *res)
{
    bool result = false;
    if (!qc || !qc->init) {
        if (res) MEMZERO(*res);
        return false;
    }
    // check if remote closed and try to reconnect
    if (!cm_conn_check_reconnect(qc)) {
        return false;
    }
    // send
    result = cm_conn_send_fd(qc->fd, req, topic, data, data_size, &qc->res);
    if (!result && (qc->res.error == CM_ERROR_CONNECT)) {
        // on connection error try to reconnect and resend
        if (!cm_conn_reopen(qc)) goto out;
        result = cm_conn_send_fd(qc->fd, req, topic, data, data_size, &qc->res);
    }
out:
    if (res) { *res = qc->res; }
    return result;
}

cm_conn_t cm_conn_log_handle;

bool cm_conn_send_log(char *msg, cm_response_t *res)
{
    cm_conn_t *qc = &cm_conn_log_handle;
    if (!qc->init) {
        cm_conn_open(qc);
    }
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = CM_DATA_LOG;
    req.compress = CM_REQ_COMPRESS_DISABLE;
    req.flags = CM_REQ_FLAG_NO_RESPONSE;
    return cm_conn_send_stream(qc, &req, NULL, msg, strlen(msg), res);
}

void cm_conn_log_close()
{
    cm_conn_t *qc = &cm_conn_log_handle;
    cm_conn_close(qc);
}


