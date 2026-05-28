#include "wpa_ctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#define LOCAL_TEMPLATE "/tmp/wpa_ctrl_%d_%ld"

struct wpa_ctrl {
    int s;
    struct sockaddr_un local;
    struct sockaddr_un dest;
};

/* helper */
static socklen_t addr_len(const struct sockaddr_un *addr)
{
    return offsetof(struct sockaddr_un, sun_path) +
           strlen(addr->sun_path);
}

/* ================= OPEN ================= */

struct wpa_ctrl *wpa_ctrl_open(const char *path)
{
    struct wpa_ctrl *ctrl = calloc(1, sizeof(*ctrl));
    if (!ctrl)
        return NULL;

    ctrl->s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ctrl->s < 0) {
        perror("socket");
        free(ctrl);
        return NULL;
    }

    /* local bind */
    ctrl->local.sun_family = AF_UNIX;
    snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
             LOCAL_TEMPLATE, getpid(), random());
    unlink(ctrl->local.sun_path);

    if (bind(ctrl->s,
             (struct sockaddr *)&ctrl->local,
             addr_len(&ctrl->local)) < 0) {
        perror("bind");
        close(ctrl->s);
        free(ctrl);
        return NULL;
    }

    /* destination */
    ctrl->dest.sun_family = AF_UNIX;
    strncpy(ctrl->dest.sun_path, path,
            sizeof(ctrl->dest.sun_path) - 1);

    if (connect(ctrl->s,
                (struct sockaddr *)&ctrl->dest,
                addr_len(&ctrl->dest)) < 0) {
        perror("connect");
        close(ctrl->s);
        unlink(ctrl->local.sun_path);
        free(ctrl);
        return NULL;
    }

    return ctrl;
}

/* ================= CLOSE ================= */

void wpa_ctrl_close(struct wpa_ctrl *ctrl)
{
    if (!ctrl)
        return;

    close(ctrl->s);
    unlink(ctrl->local.sun_path);
    free(ctrl);
}

/* ================= GET FD ================= */

int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl)
{
    return ctrl ? ctrl->s : -1;
}

/* ================= ATTACH ================= */

int wpa_ctrl_attach(struct wpa_ctrl *ctrl)
{
    if (!ctrl)
        return -1;

    if (send(ctrl->s, "ATTACH", 6, 0) < 0) {
        perror("send ATTACH");
        return -1;
    }

    /* Try to read response WITHOUT blocking */
    char buf[32];
    int len = recv(ctrl->s, buf, sizeof(buf) - 1, MSG_DONTWAIT);

    if (len > 0) {
        buf[len] = '\0';
        printf("ATTACH response: %s\n", buf);
    }

    /* Do NOT fail if no response */
    return 0;
}

/* ================= DETACH ================= */

int wpa_ctrl_detach(struct wpa_ctrl *ctrl)
{
    if (!ctrl)
        return -1;

    return send(ctrl->s, "DETACH", 6, 0);
}

/* ================= RECV ================= */

int wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *buf, size_t *len)
{
    if (!ctrl || !buf || !len)
        return -1;

    int ret = recv(ctrl->s, buf, *len, 0);

    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *len = 0;
            return 0;
        }
        perror("recv");
        return -1;
    }

    *len = ret;
    return 0;
}