// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/proxmaster.hpp>
#include <proxmasterd/web.h>
#include <nlohmann/json.hpp>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <mutex>

using json = nlohmann::json;

typedef unsigned long size_t;

struct hreq {
	struct pm_http_req *req;
	struct pm_http_res *res;
	void *arg;
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

struct route {
	uint8_t		methods[9];
	const char	*path;
	void		(*cb)(struct hreq *h);
	bool		(*auth_cb)(struct hreq *h);
};

struct route_prefix {
	const char		*prefix;
	const struct route	*routes;
};

static void rt_404(struct hreq *h)
{
	h->res->status_code = 404;
	pm_http_hdr_add(&h->res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&h->res->body, "404 Not Found!\n");
}

static void rt_400(struct hreq *h)
{
	h->res->status_code = 400;
	pm_http_hdr_add(&h->res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&h->res->body, "400 Bad Request!\n");
}

static void json_res(struct hreq *h, json j, int code)
{
	json j2 = {
		{ "status", code },
		{ "data", j }
	};

	h->res->status_code = code;
	pm_http_hdr_add(&h->res->hdr, "Content-Type", "application/json");
	pm_buf_append_fmt(&h->res->body, "%s\n", j2.dump(4, ' ').c_str());
}

static void rt_400_json(struct hreq *h, json j)
{
	json_res(h, j, 400);
}

static void rt_200_json(struct hreq *h, json j)
{
	json_res(h, j, 200);
}

static void rt_405(struct hreq *h)
{
	h->res->status_code = 405;
	pm_http_hdr_add(&h->res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&h->res->body, "405 Method Not Allowed!\n");
}

static void rt_401(struct hreq *h)
{
	h->res->status_code = 401;
	pm_http_hdr_add(&h->res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&h->res->body, "401 Unauthorized!\n");
}

static void rt_index(struct hreq *h)
{
	h->res->status_code = 200;
	pm_http_hdr_add(&h->res->hdr, "Content-Type", "text/plain");
	pm_buf_append_fmt(&h->res->body, "Hoody Proxy Manager API\n");
}

static bool rt_api_v1_auth(struct hreq *h)
{
	const char *token = getenv("PM_AUTH_TOKEN");
	char *bea;

	if (!token)
		return true;

	if (!pm_http_hdr_get(&h->req->hdr, "authorization", &bea)) {
		if (!strncmp(bea, "Bearer ", 7) && !strcmp(bea + 7, token))
			return true;
	}

	return false;
}

static void rt_api_v1_proxy_start(struct hreq *h)
{
	proxmaster *pm = static_cast<proxmaster *>(h->arg);
	const char *body = h->req->body.buf;
	auto pp = std::make_unique<proxy>();
	struct proxy &p = *pp;
	json j = json::parse(body);
	int64_t lifetime;

	if (!j.contains("proxy") || !j["proxy"].is_string()) {
		rt_400_json(h, "Missing 'proxy' string key");
		return;
	}
	p.uri_ = j["proxy"].get<std::string>();

	if (!j.contains("lifetime") || !j["lifetime"].is_number()) {
		rt_400_json(h, "Missing 'lifetime' number key");
		return;
	}
	lifetime = j["lifetime"].get<int64_t>();
	if (lifetime < 0)
		lifetime = -1;

	p.expired_at_ = lifetime ? time(nullptr) + lifetime : 0;

	if (!j.contains("port") || !j["port"].is_number()) {
		rt_400_json(h, "Missing 'port' number key");
		return;
	}
	p.port_ = j["port"].get<uint16_t>();

	if (j.contains("up_limit_bytes")) {
		if (!j["up_limit_bytes"].is_number()) {
			rt_400_json(h, "Invalid 'up_limit_bytes' number key");
			return;
		}

		p.up_limit_bytes_ = j["up_limit_bytes"].get<uint64_t>();
	}

	if (j.contains("up_limit_interval_ms")) {
		if (!j["up_limit_interval_ms"].is_number()) {
			rt_400_json(h, "Invalid 'up_limit_interval_ms' number key");
			return;
		}

		p.up_limit_interval_ms_ = j["up_limit_interval_ms"].get<uint64_t>();
	}

	if (j.contains("down_limit_bytes")) {
		if (!j["down_limit_bytes"].is_number()) {
			rt_400_json(h, "Invalid 'down_limit_bytes' number key");
			return;
		}

		p.down_limit_bytes_ = j["down_limit_bytes"].get<uint64_t>();
	}

	if (j.contains("down_limit_interval_ms")) {
		if (!j["down_limit_interval_ms"].is_number()) {
			rt_400_json(h, "Invalid 'down_limit_interval_ms' number key");
			return;
		}

		p.down_limit_interval_ms_ = j["down_limit_interval_ms"].get<uint64_t>();
	}

	if (j.contains("quota")) {
		if (!j["quota"].is_number()) {
			rt_400_json(h, "Invalid 'quota' number key");
			return;
		}

		p.quota_remaining_ = j["quota"].get<long long>();
		p.quota_enabled_ = true;
	}

	p.auth_connect_dst_ = gen_auth_conn_dst();
	p.quota_unix_control_ = pm->gen_unix_sock_path();
	p.start(pm->get_socks5_bin_file());

	if (p.proc_.exit_code_) {
		json j = {
			{ "error", "Failed to start proxy" },
			{ "cmd_output", p.proc_.err_output_ },
			{ "cmd_exit_code", p.proc_.exit_code_ },
			{ "cmd_args", p.proc_.args_ }
		};
		rt_400_json(h, j);
	} else {
		p.id_ = pm->add_proxy(std::move(pp));
		rt_200_json(h, p.to_json());
	}
}

static void rt_api_v1_proxy_stop(struct hreq *h)
{
	proxmaster *pm = static_cast<proxmaster *>(h->arg);
	const char *body = h->req->body.buf;
	json j = json::parse(body);
	int ret;

	if (!j.contains("id") || !j["id"].is_number()) {
		rt_400_json(h, "Missing 'id' number key");
		return;
	}

	unsigned long long id = j["id"].get<unsigned long long>();
	ret = pm->stop_proxy(id);
	if (ret == 0) {
		rt_200_json(h, "Proxy stopped");
	} else {
		json j = {
			{ "error", "Failed to stop proxy, ID is not found" },
			{ "id", id }
		};
		rt_400_json(h, j);
	}
}

static void rt_api_v1_proxy_list(struct hreq *h)
{
	proxmaster *pm = static_cast<proxmaster *>(h->arg);
	json j = pm->get_proxy_list();

	rt_200_json(h, j);
}

static const struct route routes[] = {
	{ { GET },	"", 		&rt_index,	nullptr },
	{ { 0 },	nullptr,	nullptr,	nullptr }
};

static const struct route api_v1_proxy[] = {
	{ { POST },	"/start",	&rt_api_v1_proxy_start,	&rt_api_v1_auth },
	{ { POST },	"/stop",	&rt_api_v1_proxy_stop,	&rt_api_v1_auth },
	{ { GET },	"/list",	&rt_api_v1_proxy_list,	&rt_api_v1_auth },
	{ { 0 },	nullptr,	nullptr,		nullptr }
};

static const struct route_prefix prefixes[] = {
	{ "/api/v1/proxy",	api_v1_proxy },
	{ "/",			routes },
	{ nullptr,		nullptr }
};

static void scan_routes(size_t plen, const struct route *routes, struct hreq *h)
{
	size_t i, j;

	for (i = 0; routes[i].path; i++) {
		if (strcmp(h->req->uri.str + plen, routes[i].path))
			continue;

		for (j = 0; routes[i].methods[j]; j++) {
			if (routes[i].methods[j] != h->req->method)
				continue;

			if (routes[i].auth_cb && !routes[i].auth_cb(h)) {
				rt_401(h);
				return;
			}

			try {
				routes[i].cb(h);
			} catch (const std::exception &e) {
				rt_400(h);
			}
			return;
		}

		rt_405(h);
		return;
	}

	rt_404(h);
}

static void scan_route_prefixes(struct pm_http_req *req, struct pm_http_res *res,
				void *arg)
{
	const char *uri = req->uri.str;
	struct hreq h;
	size_t plen;
	size_t i;

	h.req = req;
	h.res = res;
	h.arg = arg;

	for (i = 0; prefixes[i].prefix; i++) {
		plen = strlen(prefixes[i].prefix);
		if (strncmp(uri, prefixes[i].prefix, plen))
			continue;

		scan_routes(plen, prefixes[i].routes, &h);
		return;
	}

	rt_404(&h);
}

extern "C" {

void pm_web_handle_req(struct pm_http_req *req, struct pm_http_res *res, void *arg)
{
	const char *uri = req->uri.str;
	char *ua = nullptr;

	scan_route_prefixes(req, res, arg);
	if (pm_http_hdr_get(&req->hdr, "user-agent", &ua))
		ua = (char *)"Unknown";
	printf("R: %d # %s %s # %s\n", res->status_code, pm_http_method(req->method), uri, ua);
}

} /* extern "C" */
