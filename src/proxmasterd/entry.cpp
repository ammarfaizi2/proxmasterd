// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/proxmaster.hpp>
#include <proxmasterd/http.h>
#include <proxmasterd/web.h>

#include <getopt.h>
#include <string.h>
#include <stdio.h>

struct prog_arg {
	int		plain_port;
	int		ssl_port;
	int		nr_workers;
	const char	*socks5_bin_file;
	const char	*storage_dir;
	const char	*blacklist_file;
	const char	*ssl_cert_file;
	const char	*ssl_key_file;
};

static const struct option long_opts[] = {
	{ "help",		no_argument,		nullptr,	'h' },
	{ "socks5-bin-file",	required_argument,	nullptr,	'x' },
	{ "storage-dir",	required_argument,	nullptr,	's' },
	{ "blacklist-file",	required_argument,	nullptr,	'b' },
	{ "ssl-cert-file",	required_argument,	nullptr,	'c' },
	{ "ssl-key-file",	required_argument,	nullptr,	'k' },
	{ "plain-port",		required_argument,	nullptr,	'p' },
	{ "ssl-port",		required_argument,	nullptr,	'Z' },
	{ "nr-workers",		required_argument,	nullptr,	'w' },
	{ nullptr, 0, nullptr, 0 }
};
static const char short_opts[] = "hx:s:b:c:k:p:Z:w:";

static int prep_http_easy_arg(struct pm_http_easy_arg *arg, struct prog_arg *parg)
{
	memset(arg, 0, sizeof(*arg));
	arg->use_plain = (parg->plain_port > 0);
	arg->use_ssl = (parg->ssl_port > 0);

	arg->plain_port = parg->plain_port;
	arg->ssl_port = parg->ssl_port;

	arg->nr_workers = parg->nr_workers;
	if (!arg->nr_workers)
		arg->nr_workers = 4;

	arg->cert_file = parg->ssl_cert_file;
	arg->key_file = parg->ssl_key_file;

	if (!arg->use_plain && !arg->use_ssl) {
		printf("At least one of plain or SSL port must be specified\n");
		return -EINVAL;
	}

	if (arg->use_ssl && (!arg->cert_file || !arg->key_file)) {
		printf("SSL port requires both certificate and key files\n");
		return -EINVAL;
	}

	return 0;
}

static int run_pm(struct prog_arg *parg)
{
	struct pm_http_easy_arg arg;
	pm_http_ctx_t *ctx;
	int err;

	err = prep_http_easy_arg(&arg, parg);
	if (err)
		return err;

	setvbuf(stdout, nullptr, _IONBF, 0);
	err = pm_http_ctx_easy_init(&ctx, &arg);
	if (err)
		return err;

	proxmaster pm(parg->storage_dir, parg->blacklist_file, parg->socks5_bin_file);
	pm_http_ctx_set_req_cb(ctx, &pm_web_handle_req, &pm);
	pm_http_ctx_run(ctx);
	pm_http_ctx_wait(ctx);
	pm_http_ctx_stop(ctx);
	pm_http_ctx_destroy(ctx);
	return 0;
}

static void show_help(const char *app)
{
	printf("Usage: %s [OPTIONS]\n", app);
	printf("Options:\n");
	printf("  -h, --help			Show this help message\n");
	printf("  -x, --socks5-bin-file=FILE	SOCKS5 binary file\n");
	printf("  -s, --storage-dir=DIR		Storage directory\n");
	printf("  -b, --blacklist-file=FILE	Blacklist file\n");
	printf("  -c, --ssl-cert-file=FILE	SSL certificate file\n");
	printf("  -k, --ssl-key-file=FILE	SSL key file\n");
	printf("  -p, --plain-port=PORT		Plain port number\n");
	printf("  -Z, --ssl-port=PORT		SSL port number\n");
	printf("  -w, --nr-workers=NUM		Number of workers\n");
}

static int parse_arg(int argc, char *argv[], struct prog_arg *parg)
{
	int c;

	memset(parg, 0, sizeof(*parg));
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, nullptr);
		if (c < 0)
			break;

		switch (c) {
		case 'h':
			show_help(argv[0]);
			return -ESHUTDOWN;
		case 's':
			parg->storage_dir = optarg;
			break;
		case 'x':
			parg->socks5_bin_file = optarg;
			break;
		case 'b':
			parg->blacklist_file = optarg;
			break;
		case 'c':
			parg->ssl_cert_file = optarg;
			break;
		case 'k':
			parg->ssl_key_file = optarg;
			break;
		case 'p':
			parg->plain_port = atoi(optarg);
			if (parg->plain_port < 0 || parg->plain_port > 65535) {
				printf("Invalid plain port number: %d\n", parg->plain_port);
				return -EINVAL;
			}
			break;
		case 'Z':
			parg->ssl_port = atoi(optarg);
			if (parg->ssl_port < 0 || parg->ssl_port > 65535) {
				printf("Invalid SSL port number: %d\n", parg->ssl_port);
				return -EINVAL;
			}
			break;
		case 'w':
			parg->nr_workers = atoi(optarg);
			if (parg->nr_workers < 0 || parg->nr_workers > 4096) {
				printf("The number of workers must be in range [1, 4096]\n");
				return -EINVAL;
			}
			break;
		case '?':
			show_help(argv[0]);
			return -EINVAL;
		}
	}

	if (!parg->storage_dir) {
		printf("\n\n----------------------------------------\n");
		printf("    Storage directory is required!\n");
		printf("----------------------------------------\n\n\n");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (!parg->socks5_bin_file) {
		printf("\n\n----------------------------------------\n");
		printf("    SOCKS5 binary file is required!\n");
		printf("----------------------------------------\n\n\n");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (!parg->blacklist_file)
		parg->blacklist_file = "";

	return 0;
}

int main(int argc, char *argv[])
{
	struct prog_arg parg;
	int ret;

	ret = parse_arg(argc, argv, &parg);
	if (ret)
		return -ret;

	return -run_pm(&parg);
}
