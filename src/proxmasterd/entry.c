// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/net.h>
#include <string.h>

int main(int argc, char *argv[])
{
	struct pm_net_ctx_arg arg;
	struct pm_net_ctx ctx;
	int err;

	memset(&arg.bind_addr, 0, sizeof(arg.bind_addr));
	arg.bind_addr.v6.sin6_family = AF_INET6;
	arg.bind_addr.v6.sin6_port = htons(8080);
	arg.bind_addr.v6.sin6_addr = in6addr_any;
	arg.sock_backlog = 4096;
	arg.client_init_cap = 1024;
	arg.nr_workers = 4;
	err = pm_net_ctx_init(&ctx, &arg);
	if (err)
		return err;

	pm_net_ctx_run(&ctx);
	pm_net_ctx_wait(&ctx);
	pm_net_ctx_stop(&ctx);
	pm_net_ctx_destroy(&ctx);
	return 0;
}
