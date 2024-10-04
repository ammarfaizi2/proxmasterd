// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__NET_H
#define PROXMASTERD__NET_H

#include <netinet/in.h>
#include <stdbool.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sockaddr_in46 {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	};
};

struct pm_buf {
	size_t		len;
	size_t		cap;
	char		*buf;
};

struct pm_net_tcp_ctx;
typedef struct pm_net_tcp_ctx pm_net_tcp_ctx_t;
typedef struct pm_net_tcp_client pm_net_tcp_client_t;
typedef int (*pm_net_tcp_recv_cb_t)(pm_net_tcp_client_t *c);
typedef int (*pm_net_tcp_send_cb_t)(pm_net_tcp_client_t *c);
typedef int (*pm_net_tcp_close_cb_t)(pm_net_tcp_client_t *c);
typedef int (*pm_net_tcp_accept_cb_t)(pm_net_tcp_ctx_t *ctx, pm_net_tcp_client_t *c);

struct pm_stack_u32 {
	size_t		bp;
	size_t		sp;
	uint32_t	*arr;
	pthread_mutex_t	lock;
};

struct pm_net_tcp_arg {
	uint16_t		nr_workers;
	uint32_t		client_init_cap;
	int			sock_backlog;
	struct sockaddr_in46	bind_addr;
};

int __pm_stack_u32_push(struct pm_stack_u32 *s, uint32_t v);
int pm_stack_u32_push(struct pm_stack_u32 *s, uint32_t v);
int __pm_stack_u32_pop(struct pm_stack_u32 *s, uint32_t *v);
int pm_stack_u32_pop(struct pm_stack_u32 *s, uint32_t *v);

int pm_buf_init(struct pm_buf *b, size_t cap);
int pm_buf_append(struct pm_buf *b, const void *data, size_t len);
int pm_buf_append_fmt(struct pm_buf *b, const void *fmt, ...);
int pm_buf_resize(struct pm_buf *b, size_t new_cap);
void pm_buf_destroy(struct pm_buf *b);

int pm_net_tcp_ctx_init(pm_net_tcp_ctx_t **ctx_p, const struct pm_net_tcp_arg *arg);
void pm_net_tcp_ctx_run(pm_net_tcp_ctx_t *ctx);
void pm_net_tcp_ctx_wait(pm_net_tcp_ctx_t *ctx);
void pm_net_tcp_ctx_stop(pm_net_tcp_ctx_t *ctx);
void pm_net_tcp_ctx_destroy(pm_net_tcp_ctx_t *ctx);

void pm_net_tcp_ctx_set_udata(pm_net_tcp_ctx_t *ctx, void *udata);
void *pm_net_tcp_ctx_get_udata(pm_net_tcp_ctx_t *ctx);
void pm_net_tcp_ctx_set_accept_cb(pm_net_tcp_ctx_t *ctx, pm_net_tcp_accept_cb_t accept_cb);

void pm_net_tcp_client_set_udata(pm_net_tcp_client_t *c, void *udata);
void *pm_net_tcp_client_get_udata(pm_net_tcp_client_t *c);
void pm_net_tcp_client_set_recv_cb(pm_net_tcp_client_t *c, pm_net_tcp_recv_cb_t recv_cb);
void pm_net_tcp_client_set_send_cb(pm_net_tcp_client_t *c, pm_net_tcp_send_cb_t send_cb);
void pm_net_tcp_client_set_close_cb(pm_net_tcp_client_t *c, pm_net_tcp_close_cb_t close_cb);

struct pm_buf *pm_net_tcp_client_get_recv_buf(pm_net_tcp_client_t *c);
struct pm_buf *pm_net_tcp_client_get_send_buf(pm_net_tcp_client_t *c);
const struct sockaddr_in46 *pm_net_tcp_client_get_src_addr(pm_net_tcp_client_t *c);

void pm_net_tcp_client_user_close(pm_net_tcp_client_t *c);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef PROXMASTERD__NET_H */
