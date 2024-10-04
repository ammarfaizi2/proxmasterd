// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__PROXMASTER_H
#define PROXMASTERD__PROXMASTER_H

#include <nlohmann/json.hpp>
#include <vector>
#include <cstdint>
#include <string>

enum {
	PROX_ENT_ST_RUNNING,
	PROX_ENT_ST_STOPPED,
};

struct prox_bpr {
	using json = nlohmann::json;
	pid_t		pid;
	std::string	cmd;
	std::vector<std::string> args;

	prox_bpr(void);
	~prox_bpr(void);
	json to_json(void) const;
	void from_json(const json &j);
	int exec_cmd(void);
	void set_args(const std::vector<std::string> &args);
};

struct prox_ent {
	using json = nlohmann::json;

	uint8_t		state;
	uint64_t	id;
	uint64_t	expired_at;
	std::string	proxy;
	std::string	auth_connect_whitelist;
	struct prox_bpr	tun2socks;
	struct prox_bpr	hev_proxy;

	prox_ent(void);
	~prox_ent(void);
	json to_json(void) const;
	void from_json(const json &j);

	static const char *state_int_to_str(uint8_t state);
	static uint8_t state_str_to_int(const char *state);
};

struct prox_ent_arr {
	using json = nlohmann::json;

	std::vector<prox_ent> arr;

	void add(const prox_ent &ent);
	json to_json(void) const;
	void from_json(const json &j);
	void from_file(const char *file);
	void to_file(const char *file) const;
};

#endif /* #ifndef PROXMASTERD__WEB_H */
