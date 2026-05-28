#ifndef WPA_CTRL_H
#define WPA_CTRL_H

#include <stddef.h>

struct wpa_ctrl;

struct wpa_ctrl *wpa_ctrl_open(const char *path);
void wpa_ctrl_close(struct wpa_ctrl *ctrl);

int wpa_ctrl_attach(struct wpa_ctrl *ctrl);
int wpa_ctrl_detach(struct wpa_ctrl *ctrl);

int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl);

int wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *buf, size_t *len);

#endif