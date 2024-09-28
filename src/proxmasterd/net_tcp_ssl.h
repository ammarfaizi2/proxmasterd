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

int pm_net_tcp_ssl_ctx_init(pm_net_tcp_ssl_ctx_t **ctx_p, const struct pm_net_tcp_ssl_arg *arg);
void pm_net_tcp_ssl_ctx_run(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_wait(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_stop(pm_net_tcp_ssl_ctx_t *ctx);
void pm_net_tcp_ssl_ctx_destroy(pm_net_tcp_ssl_ctx_t *ctx_p);

#endif /* #ifndef PROXMASTERD__NET_SSL_H */
