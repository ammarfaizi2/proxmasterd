// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/web.h>
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>

struct route {
	uint8_t		methods[9];
	const char	*path;
	void		(*cb)(struct pm_http_req *req, struct pm_http_res *res);
};

enum {
	POST = PM_HTTP_METHOD_POST,
	GET = PM_HTTP_METHOD_GET,
	PUT = PM_HTTP_METHOD_PUT,
	DELETE = PM_HTTP_METHOD_DELETE,
	HEAD = PM_HTTP_METHOD_HEAD,
	OPTIONS = PM_HTTP_METHOD_OPTIONS,
	TRACE = PM_HTTP_METHOD_TRACE,
	CONNECT = PM_HTTP_METHOD_CONNECT,
	PATCH = PM_HTTP_METHOD_PATCH
};

static void rt_404(struct pm_http_req *req, struct pm_http_res *res)
{
	res->status_code = 404;
	pm_http_hdr_add(&res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&res->body, "404 Not Found!\n");
}

static void rt_405(struct pm_http_req *req, struct pm_http_res *res)
{
	res->status_code = 405;
	pm_http_hdr_add(&res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&res->body, "405 Method Not Allowed!\n");
}

static void rt_index(struct pm_http_req *req, struct pm_http_res *res)
{
	res->status_code = 200;
	pm_http_hdr_add(&res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&res->body, "Hello, World!\n");
}

static const struct route routes[] = {
	{ { GET }, "/", rt_index },
};

static void handle_routes(struct pm_http_req *req, struct pm_http_res *res)
{
	const char *uri = req->uri.str;
	size_t i, j, len;

	len = (sizeof(routes) / sizeof(routes[0]));
	for (i = 0; i < len; i++) {
		if (strcmp(uri, routes[i].path))
			continue;

		for (j = 0; j < 9; j++) {
			if (routes[i].methods[j] == req->method) {
				routes[i].cb(req, res);
				return;
			}
		}

		rt_405(req, res);
		return;
	}

	rt_404(req, res);
}

void pm_web_handle_req(struct pm_http_req *req, struct pm_http_res *res, void *arg)
{
	const char *uri = req->uri.str;
	char *ua = NULL;

	handle_routes(req, res);

	if (pm_http_hdr_get(&req->hdr, "user-agent", &ua))
		ua = (char *)"Unknown";
	printf("R: %d # %s %s # %s\n", res->status_code, pm_http_method(req->method), uri, ua);
}
