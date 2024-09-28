// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__NET_SSL_H
#define PROXMASTERD__NET_SSL_H

#include <proxmasterd/net_tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

struct pm_net_tcp_ssl_arg {
	char				cert_file[512];
	char				key_file[512];
	struct pm_net_tcp_arg		net_arg;
};

struct pm_net_tcp_ssl_ctx;
struct pm_net_tcp_ssl_client;
typedef struct pm_net_tcp_ssl_ctx pm_net_tcp_ssl_ctx_t;
typedef struct pm_net_tcp_ssl_client pm_net_tcp_ssl_client_t;
typedef int (*pm_net_tcp_ssl_recv_cb_t)(pm_net_tcp_ssl_client_t *c);
typedef int (*pm_net_tcp_ssl_send_cb_t)(pm_net_tcp_ssl_client_t *c);
typedef int (*pm_net_tcp_ssl_close_cb_t)(pm_net_tcp_ssl_client_t *c);
typedef int (*pm_net_tcp_ssl_accept_cb_t)(pm_net_tcp_ssl_ctx_t *ctx, pm_net_tcp_ssl_client_t *c);

int pm_net_tcp_ssl_ctx_init(pm_net_tcp_ssl_ctx_t **ctx_p, const struct pm_net_tcp_ssl_arg *arg);
void pm_net_tcp_ssl_ctx_run(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_wait(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_stop(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_destroy(pm_net_tcp_ssl_ctx_t *ctx_p);

void pm_net_tcp_ssl_ctx_set_udata(pm_net_tcp_ssl_ctx_t *ctx, void *udata);
void *pm_net_tcp_ssl_ctx_get_udata(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_set_accept_cb(pm_net_tcp_ssl_ctx_t *ctx, pm_net_tcp_ssl_accept_cb_t accept_cb);

void pm_net_tcp_ssl_client_set_udata(pm_net_tcp_ssl_client_t *c, void *udata);
void *pm_net_tcp_ssl_client_get_udata(pm_net_tcp_ssl_client_t *c);
void pm_net_tcp_ssl_client_set_recv_cb(pm_net_tcp_ssl_client_t *c, pm_net_tcp_ssl_recv_cb_t recv_cb);
void pm_net_tcp_ssl_client_set_send_cb(pm_net_tcp_ssl_client_t *c, pm_net_tcp_ssl_send_cb_t send_cb);
void pm_net_tcp_ssl_client_set_close_cb(pm_net_tcp_ssl_client_t *c, pm_net_tcp_ssl_close_cb_t close_cb);

struct pm_buf *pm_net_tcp_ssl_client_get_recv_buf(pm_net_tcp_ssl_client_t *c);
struct pm_buf *pm_net_tcp_ssl_client_get_send_buf(pm_net_tcp_ssl_client_t *c);
const struct sockaddr_in46 *pm_net_tcp_ssl_client_get_src_addr(pm_net_tcp_ssl_client_t *c);

void pm_net_tcp_ssl_client_user_close(pm_net_tcp_ssl_client_t *c);

#endif /* #ifndef PROXMASTERD__NET_SSL_H */
