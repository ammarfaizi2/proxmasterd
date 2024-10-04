// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__HTTP_H
#define PROXMASTERD__HTTP_H

#include <proxmasterd/net_tcp.h>
#include <proxmasterd/net_tcp_ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	PM_HTTP_NET_CTX_PLAIN	= 0,
	PM_HTTP_NET_CTX_SSL	= 1
};

enum {
	PM_HTTP_METHOD_GET	= 1,
	PM_HTTP_METHOD_POST	= 2,
	PM_HTTP_METHOD_PUT	= 3,
	PM_HTTP_METHOD_DELETE	= 4,
	PM_HTTP_METHOD_HEAD	= 5,
	PM_HTTP_METHOD_OPTIONS	= 6,
	PM_HTTP_METHOD_TRACE	= 7,
	PM_HTTP_METHOD_CONNECT	= 8,
	PM_HTTP_METHOD_PATCH	= 9
};

enum {
	PM_HTTP_VER_09	= 0,
	PM_HTTP_VER_10	= 1,
	PM_HTTP_VER_11	= 2,
	PM_HTTP_VER_20	= 3,
	PM_HTTP_VER_30	= 4,
	PM_HTTP_VER_31	= 5,
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

struct pm_http_str {
	char		*str;
	size_t		len;
};

struct pm_http_req {
	uint8_t			method;
	uint8_t			ver;
	uint64_t		content_length;
	uint64_t		cl_remain;
	struct pm_http_str	uri;
	struct pm_http_str	qs;
	struct pm_http_hdr	hdr;
	struct pm_buf		body;
};

struct pm_http_res {
	uint8_t			ver;
	uint16_t		status_code;
	struct pm_http_hdr	hdr;
	struct pm_buf		body;
};

typedef void (*pm_http_req_cb_t)(struct pm_http_req *req, struct pm_http_res *res, void *arg);

int pm_http_hdr_add(struct pm_http_hdr *hdr, const char *key, const char *val);
int pm_http_hdr_get(struct pm_http_hdr *hdr, const char *key, char **val);

int pm_http_ctx_init(pm_http_ctx_t **ctx_p);
int pm_http_ctx_add_net_ctx(pm_http_ctx_t *ctx, pm_http_net_ctx_t *net_ctx, uint8_t type);
int pm_http_ctx_easy_init(pm_http_ctx_t **ctx_p, const struct pm_http_easy_arg *arg);
void pm_http_ctx_set_req_cb(pm_http_ctx_t *ctx, pm_http_req_cb_t cb, void *arg);
const char *pm_http_method(uint8_t method);

void pm_http_ctx_run(pm_http_ctx_t *ctx);
void pm_http_ctx_wait(pm_http_ctx_t *ctx);
void pm_http_ctx_stop(pm_http_ctx_t *ctx);
void pm_http_ctx_destroy(pm_http_ctx_t *ctx_p);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef PROXMASTERD__HTTP_H */
