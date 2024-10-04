// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/proxmaster.hpp>
#include <proxmasterd/http.h>
#include <proxmasterd/web.h>
#include <string.h>
#include <stdio.h>

static void set_arg(struct pm_http_easy_arg *arg, const char *cert, const char *key)
{
	arg->use_plain = true;
	arg->use_ssl = true;
	arg->plain_port = 8080;
	arg->ssl_port = 8443;
	arg->nr_workers = 4;
	arg->cert_file = cert;
	arg->key_file = key;
}

int main(int argc, char *argv[])
{
	struct pm_http_easy_arg arg;
	pm_http_ctx_t *ctx;
	prox_ent_arr pea;
	int err;

	pea.from_file("./proxmaster.json");
	setvbuf(stdout, nullptr, _IONBF, 0);
	set_arg(&arg, "./q.pem", "./q.key");
	err = pm_http_ctx_easy_init(&ctx, &arg);
	if (err)
		return err;

	pm_http_ctx_set_req_cb(ctx, &pm_web_handle_req, &pea);
	pm_http_ctx_run(ctx);
	pm_http_ctx_wait(ctx);
	pm_http_ctx_stop(ctx);
	pm_http_ctx_destroy(ctx);
	return 0;
}
