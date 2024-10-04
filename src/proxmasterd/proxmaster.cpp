// SPDX-License-Identifier: GPL-2.0-only
#include <proxmasterd/proxmaster.hpp>
#include <fstream>
#include <unistd.h>

using json = nlohmann::json;

prox_bpr::prox_bpr(void):
	pid(0)
{
}

prox_bpr::~prox_bpr(void) = default;

int prox_bpr::exec_cmd(void)
{
	pid_t p;

	p = fork();
	if (p < 0)
		return -1;

	if (p == 0) {
		std::vector<char *> argv;

		argv.push_back(const_cast<char *>(cmd.c_str()));
		for (const auto &arg : args)
			argv.push_back(const_cast<char *>(arg.c_str()));
		argv.push_back(nullptr);

		execvp(cmd.c_str(), argv.data());
		exit(1);
	}

	return 0;
}

void prox_bpr::set_args(const std::vector<std::string> &args)
{
	this->args = args;
}

json prox_bpr::to_json(void) const
{
	json j = {
		{ "pid", pid },
		{ "cmd", cmd },
		{ "args", args }
	};

	return j;
}

void prox_bpr::from_json(const json &j)
{
	prox_bpr bpr;

	if (j.find("pid") != j.end())
		bpr.pid = j["pid"].get<pid_t>();
	if (j.find("cmd") != j.end())
		bpr.cmd = j["cmd"].get<std::string>();
	if (j.find("args") != j.end() && j["args"].is_array())
		bpr.args = j["args"].get<std::vector<std::string>>();
}

prox_ent::prox_ent(void):
	state(PROX_ENT_ST_STOPPED),
	id(0),
	expired_at(0)
{
}

prox_ent::~prox_ent(void) = default;

const char *prox_ent::state_int_to_str(uint8_t state)
{
	switch (state) {
	case PROX_ENT_ST_RUNNING:
		return "running";
	case PROX_ENT_ST_STOPPED:
		return "stopped";
	default:
		return "unknown";
	}
}

uint8_t prox_ent::state_str_to_int(const char *state)
{
	if (!strcmp(state, "running"))
		return PROX_ENT_ST_RUNNING;
	else if (!strcmp(state, "stopped"))
		return PROX_ENT_ST_STOPPED;
	else
		return 0;
}

json prox_ent::to_json(void) const
{
	json j = {
		{ "state", state_int_to_str(state) },
		{ "id", id },
		{ "expired_at", expired_at },
		{ "proxy", proxy },
		{ "auth_connect_whitelist", auth_connect_whitelist },
		{ "tun2socks", tun2socks.to_json() },
		{ "hev_proxy", hev_proxy.to_json() }
	};

	return j;
}

void prox_ent::from_json(const json &j)
{
	prox_ent ent;

	if (j.find("state") != j.end())
		ent.state = state_str_to_int(j["state"].get<std::string>().c_str());
	if (j.find("id") != j.end())
		ent.id = j["id"].get<uint64_t>();
	if (j.find("expired_at") != j.end())
		ent.expired_at = j["expired_at"].get<uint64_t>();
	if (j.find("proxy") != j.end())
		ent.proxy = j["proxy"].get<std::string>();
	if (j.find("auth_connect_whitelist") != j.end())
		ent.auth_connect_whitelist = j["auth_connect_whitelist"].get<std::string>();
	if (j.find("tun2socks") != j.end())
		ent.tun2socks.from_json(j["tun2socks"]);
	if (j.find("hev_proxy") != j.end())
		ent.hev_proxy.from_json(j["hev_proxy"]);
}

void prox_ent_arr::add(const prox_ent &ent)
{
	arr.push_back(ent);
}

json prox_ent_arr::to_json(void) const
{
	json j = {
		{ "entries", json::array() }
	};

	for (const auto &ent : arr)
		j["entries"].push_back(ent.to_json());
	
	return j;
}

void prox_ent_arr::from_json(const json &j)
{
	if (j.find("entries") == j.end() || !j["entries"].is_array())
		return;

	for (const auto &ent : j["entries"]) {
		try {
			prox_ent tmp;
			tmp.from_json(ent);
			arr.push_back(tmp);
		} catch (...) {
			continue;
		}
	}
}

void prox_ent_arr::from_file(const char *file)
{
	try {
		std::ifstream ifs(file);
		json j;

		if (!ifs.is_open())
			return;
		ifs >> j;
		ifs.close();

		from_json(j);
	} catch (...) {
		return;
	}
}

void prox_ent_arr::to_file(const char *file) const
{
	try {
		std::ofstream ofs(file);
		json j = to_json();

		if (!ofs.is_open())
			return;

		ofs << j.dump(1, '\t') << std::endl;
		ofs.close();
	} catch (...) {
		return;
	}
}
