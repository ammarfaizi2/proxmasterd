// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__HTTP_H
#define PROXMASTERD__HTTP_H

#include <proxmasterd/net_tcp.h>
#include <proxmasterd/net_tcp_ssl.h>

enum {
	PM_HTTP_NET_CTX_PLAIN	= 0,
	PM_HTTP_NET_CTX_SSL	= 1
};

struct pm_http_net_ctx;
struct pm_http_ctx;
typedef struct pm_http_net_ctx pm_http_net_ctx_t;
typedef struct pm_http_ctx pm_http_ctx_t;

struct pm_http_net_ctx {
	union {
		pm_net_tcp_ctx_t	*plain;
		pm_net_tcp_ssl_ctx_t	*ssl;
	};
};

struct pm_http_easy_arg {
	bool		use_plain;
	bool		use_ssl;
	uint16_t	plain_port;
	uint16_t	ssl_port;
	uint16_t	nr_workers;
	const char	*cert_file;
	const char	*key_file;
};

int pm_http_ctx_init(pm_http_ctx_t **ctx_p);
int pm_http_ctx_add_net_ctx(pm_http_ctx_t *ctx, pm_http_net_ctx_t *net_ctx, uint8_t type);
int pm_http_ctx_easy_init(pm_http_ctx_t **ctx_p, const struct pm_http_easy_arg *arg);

void pm_http_ctx_run(pm_http_ctx_t *ctx);
void pm_http_ctx_wait(pm_http_ctx_t *ctx);
void pm_http_ctx_stop(pm_http_ctx_t *ctx);
void pm_http_ctx_destroy(pm_http_ctx_t *ctx_p);

#endif /* #ifndef PROXMASTERD__HTTP_H */
