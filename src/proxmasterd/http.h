// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__HTTP_H
#define PROXMASTERD__HTTP_H

#include <proxmasterd/net_tcp.h>
#include <proxmasterd/net_tcp_ssl.h>

enum {
	PM_HTTP_NET_CTX_PLAIN	= 0,
	PM_HTTP_NET_CTX_SSL	= 1
};

enum {
	PM_HTTP_METHOD_GET	= 0,
	PM_HTTP_METHOD_POST	= 1,
	PM_HTTP_METHOD_PUT	= 2,
	PM_HTTP_METHOD_DELETE	= 3,
	PM_HTTP_METHOD_HEAD	= 4,
	PM_HTTP_METHOD_OPTIONS	= 5,
	PM_HTTP_METHOD_TRACE	= 6,
	PM_HTTP_METHOD_CONNECT	= 7,
	PM_HTTP_METHOD_PATCH	= 8
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

struct pm_http_hdr_pair {
	char		*key;
	char		*val;
	uint16_t	key_len;
	uint16_t	val_len;
};

struct pm_http_hdr {
	size_t				nr_pairs;
	struct pm_http_hdr_pair		*pairs;
};

int pm_http_hdr_add(struct pm_http_hdr *hdr, const char *key, const char *val);

int pm_http_ctx_init(pm_http_ctx_t **ctx_p);
int pm_http_ctx_add_net_ctx(pm_http_ctx_t *ctx, pm_http_net_ctx_t *net_ctx, uint8_t type);
int pm_http_ctx_easy_init(pm_http_ctx_t **ctx_p, const struct pm_http_easy_arg *arg);

void pm_http_ctx_run(pm_http_ctx_t *ctx);
void pm_http_ctx_wait(pm_http_ctx_t *ctx);
void pm_http_ctx_stop(pm_http_ctx_t *ctx);
void pm_http_ctx_destroy(pm_http_ctx_t *ctx_p);

#endif /* #ifndef PROXMASTERD__HTTP_H */
