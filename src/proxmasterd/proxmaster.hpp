// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__PROXMASTER_H
#define PROXMASTERD__PROXMASTER_H

#include <nlohmann/json.hpp>
#include <condition_variable>
#include <vector>
#include <cstdint>
#include <string>
#include <mutex>
#include <thread>

#include <cstdio>

enum {
	PROXY_TYPE_SOCKS5
};

struct proxy_proc {
	using json = nlohmann::json;

	int				exit_code_ = 0;
	pid_t				pid_ = -1;
	std::vector<std::string>	args_;
	std::string			err_output_ = "";	/* Error output */

	proxy_proc(void);
	~proxy_proc(void);

	json to_json(void);
	void from_json(const json &j);
	void start(void);
	void stop(void);
};

struct proxy {
	using json = nlohmann::json;

	uint8_t			type_ = PROXY_TYPE_SOCKS5;
	std::string		uri_ = "";		/* URI to proxy */
	std::string		auth_connect_dst_ = "";	/* Destination to connect for auth */
	int64_t			expired_at_ = 0;	/* Unix timestamp */
	int64_t			started_at_ = 0;	/* Unix timestamp */
	uint16_t		port_ = 0;

	uint64_t		up_limit_bytes_ = 0;
	uint64_t		up_limit_interval_ms_ = 0;
	uint64_t		down_limit_bytes_ = 0;
	uint64_t		down_limit_interval_ms_ = 0;
	long long		quota_remaining_ = 0;
	bool			quota_enabled_ = false;
	bool			quota_exceeded_ = false;

	unsigned long long	id_;
	struct proxy_proc	proc_;

	proxy(void);
	~proxy(void);

	json to_json(void);
	void from_json(const json &j);

	void to_file(const std::string &path);
	void from_file(const std::string &path);
	void start(const std::string &bin_path);
	void stop(void);
	void sync_quota(void);

	std::string		quota_unix_control_ = "";
	struct qo_cl		*qo_cl_ = nullptr;

	static inline void copy(proxy &dst, proxy &src)
	{
		dst = src;

		// Move qo_cl_, avoid double free.
		src.qo_cl_ = nullptr;
	}
};

std::string gen_auth_conn_dst(void);

class proxmaster {
	using json = nlohmann::json;

private:
	std::vector<std::unique_ptr<proxy>>		proxies_;
	std::vector<std::string>			blacklist_;
	std::string					storage_dir_ = "";
	std::string					blacklist_file_ = "";
	std::string					socks5_bin_file_ = "";
	unsigned long long				last_id_;
	std::mutex					lock_;
	FILE						*f_last_id_ = nullptr;
	std::thread					reaper_thread_;
	std::condition_variable				reaper_cv_;
	bool						reaper_stop_ = false;
public:
	proxmaster(const std::string &storage_dir, const std::string &blacklist_file,
		   const std::string &socks5_bin_file);
	~proxmaster(void);

	void load_blacklist(void);
	void load_proxies(void);
	void save_proxies(void);
	void start_proxies(void);
	void save_last_id(void);
	void delete_proxy_file(unsigned long long id);

	json get_proxy_list(void);

	unsigned long long add_proxy(std::unique_ptr<proxy> p);
	void __stop_proxy(proxy &p);
	int stop_proxy(unsigned long long id);
	void reaper(void);
	json quota_cmd(const std::string &cmd, long long arg, unsigned long long id, int *ret);

	const inline std::string get_unix_sock_dir(void) const
	{
		return storage_dir_ + "/unix_socks";
	}

	inline std::string gen_unix_sock_path(void)
	{
		return get_unix_sock_dir() +
			"/p" +
			std::to_string(time(nullptr)) +
			"_" +
			std::to_string(rand() % 1000) +
			std::to_string(rand() % 1000) +
			std::to_string(rand() % 1000) +
			".sock";
	}

	const inline std::string get_socks5_bin_file(void) const
	{
		return socks5_bin_file_;
	}
};

#endif /* #ifndef PROXMASTERD__WEB_H */
