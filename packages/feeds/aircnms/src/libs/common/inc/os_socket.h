#ifndef OS_SOCKET_H_INCLUDED
#define OS_SOCKET_H_INCLUDED

#include <stdbool.h>

//Anjan
#include "MT7621.h"

#define SOCKET_ADDR_ANY        "0.0.0.0"
#define SOCKET_ADDR_LOCALHOST  "127.0.0.1"
#define OVSDB_SOCK_PATH        CONFIG_TARGET_PATH_OVSDB_SOCK
#define ENV_OVSDB_SOCK_PATH    "PLUME_OVSDB_SOCK_PATH"

typedef enum
{
    OS_SOCK_TYPE_UDP,
    OS_SOCK_TYPE_TCP
}
os_sock_type;

extern bool socket_set_keepalive(int fd);

/*
 * Socket related definitions
 */
typedef bool socket_cbk_t(int fd,
                          char *msg,
                          size_t msgsz,
                          void *ctx);

/**
 * Socket Related definitions
 */
int32_t server_socket_create(os_sock_type sock_type,
                             char *listen_addr,
                             uint32_t server_port);

int32_t client_socket_create(os_sock_type sock_type);

bool client_connect(int32_t sock_fd,
                    char *server_addr,
                    uint32_t port);

int32_t tcp_server_listen(int32_t sock_fd);

/* open ovsdb server socket */
int ovsdb_conn();
bool ovsdb_disconn(int sock_fd);

#endif  /* OS_SOCKET_H_INCLUDED */
