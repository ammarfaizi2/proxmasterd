// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__NET_SSL_H
#define PROXMASTERD__NET_SSL_H

#include <proxmasterd/net.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

struct pm_net_ssl_ctx_arg {
	char			cert_file[512];
	char			key_file[512];
	struct pm_net_ctx_arg	net_ctx_arg;
};

struct pm_net_ssl_ctx {
	SSL_CTX				*ssl_ctx;
	struct pm_net_ctx		net_ctx;
	struct pm_net_ssl_ctx_arg	arg;
};

int pm_net_ssl_ctx_init(struct pm_net_ssl_ctx *ctx, const struct pm_net_ssl_ctx_arg *arg);
void pm_net_ssl_ctx_run(struct pm_net_ssl_ctx *ctx);
void pm_net_ssl_ctx_wait(struct pm_net_ssl_ctx *ctx);
void pm_net_ssl_ctx_stop(struct pm_net_ssl_ctx *ctx);
void pm_net_ssl_ctx_destroy(struct pm_net_ssl_ctx *ctx);

#endif /* #ifndef PROXMASTERD__NET_SSL_H */
