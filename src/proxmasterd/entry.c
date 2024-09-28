// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/net_tcp_ssl.h>
#include <string.h>

static void set_arg(struct pm_net_tcp_ssl_arg *arg, const char *cert, const char *key)
{
	struct pm_net_tcp_arg *net_arg = &arg->net_arg;

	memset(arg, 0, sizeof(*arg));
	strncpy(arg->cert_file, cert, sizeof(arg->cert_file) - 1);
	strncpy(arg->key_file, key, sizeof(arg->key_file) - 1);
	net_arg->bind_addr.v6.sin6_family = AF_INET6;
	net_arg->bind_addr.v6.sin6_port = htons(8080);
	net_arg->bind_addr.v6.sin6_addr = in6addr_any;
	net_arg->sock_backlog = 4096;
	net_arg->client_init_cap = 1024;
	net_arg->nr_workers = 4;
}

int main(int argc, char *argv[])
{
	struct pm_net_tcp_ssl_arg arg;
	pm_net_tcp_ssl_ctx_t *ctx;
	int err;

	set_arg(&arg, "./q.pem", "./q.key");
	err = pm_net_tcp_ssl_ctx_init(&ctx, &arg);
	if (err)
		return -err;

	pm_net_tcp_ssl_ctx_run(ctx);
	pm_net_tcp_ssl_ctx_wait(ctx);
	pm_net_tcp_ssl_ctx_destroy(ctx);
	return 0;
}
