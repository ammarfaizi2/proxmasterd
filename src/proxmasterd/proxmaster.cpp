// SPDX-License-Identifier: GPL-2.0-only
#include <proxmasterd/proxmaster.hpp>
#include <cstddef>

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <errno.h>

typedef unsigned long size_t;

using json = nlohmann::json;

static bool is_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return false;

	return S_ISDIR(st.st_mode);
}

static bool is_file(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return false;

	return S_ISREG(st.st_mode);
}

static bool mkdir_recursive(const char *path)
{
	char *p, *dir;
	int ret;

	dir = strdup(path);
	if (!dir)
		return false;

	for (p = dir + 1; *p; p++) {
		if (*p != '/')
			continue;

		*p = '\0';
		ret = mkdir(dir, 0755);
		if (ret < 0 && errno != EEXIST) {
			free(dir);
			return false;
		}
		*p = '/';
	}

	ret = mkdir(dir, 0755);
	free(dir);

	return (ret == 0 || errno == EEXIST) && is_dir(path);
}

proxy_proc::proxy_proc(void)
{
}

proxy_proc::~proxy_proc(void)
{
}

json proxy_proc::to_json(void)
{
	return {
		{ "pid", pid_ },
		{ "args", args_ },
		{ "exit_code", exit_code_ },
		{ "err_output", err_output_ }
	};
}

void proxy_proc::from_json(const json &j)
{
	pid_ = j["pid"];
	args_ = j["args"];
	err_output_ = j["err_output"];
	exit_code_ = j["exit_code"];
}

void proxy_proc::start(void)
{	
	const uint32_t wait_seconds = 30;
	uint32_t wait_attempts = 0;
	int ret, status;
	char buf[4096];
	int pfd[2];

	if (pipe2(pfd, O_NONBLOCK) < 0)
		throw std::runtime_error("Failed to create pipe: " + std::string(strerror(errno)));

	pid_ = fork();
	if (pid_ < 0) {
		close(pfd[0]);
		close(pfd[1]);
		throw std::runtime_error("Failed to fork: " + std::string(strerror(errno)));
	}

	if (!pid_) {
		std::vector<char *> argv;

		for (auto &a : args_)
			argv.push_back(const_cast<char *>(a.c_str()));
		argv.push_back(nullptr);

		dup2(pfd[1], 1);
		dup2(pfd[1], 2);
		close(pfd[0]);
		close(pfd[1]);
		execvp(argv[0], argv.data());
		exit(1);
	}

	while (1) {
		uint32_t secs;

		usleep(100000);

		wait_attempts++;
		memset(buf, 0, sizeof(buf));
		ret = read(pfd[0], buf, sizeof(buf));
		if (ret < 0)
			break;

		if (strstr(buf, "Listening on"))
			break;

		ret = waitpid(pid_, &status, WNOHANG);
		if (ret == pid_) {
			err_output_ = buf;
			exit_code_ = WEXITSTATUS(status);
			break;
		}

		secs = wait_attempts / 10;
		if (secs > wait_seconds) {
			kill(pid_, SIGTERM);
			err_output_ = "Failed to start proxy: Timeout!";
			exit_code_ = 1;
			break;
		}
	}

	close(pfd[0]);
	close(pfd[1]);
}

void proxy_proc::stop(void)
{
	if (pid_ > 0) {
		int status;

		kill(pid_, SIGTERM);
		waitpid(pid_, &status, 0);

		pid_ = -1;
		exit_code_ = WEXITSTATUS(status);
		err_output_ = "";
		args_.clear();
	}
}

proxy::proxy(void) = default;
proxy::~proxy(void) = default;

void proxy::stop(void)
{
	proc_.stop();
}

void proxy::start(const std::string &bin_path)
{
	std::vector<std::string> &args = proc_.args_;

	args.clear();
	args.push_back(bin_path);
	args.push_back("--workers");
	args.push_back("4");
	args.push_back("--bind");
	args.push_back("0.0.0.0:" + std::to_string(port_));
	args.push_back("--as-socks5");
	args.push_back("--to-socks5");
	args.push_back(uri_);

	if (up_limit_bytes_ && up_limit_interval_ms_) {
		args.push_back("--up-limit");
		args.push_back(std::to_string(up_limit_bytes_));
		args.push_back("--up-interval");
		args.push_back(std::to_string(up_limit_interval_ms_));
	}

	if (down_limit_bytes_ && down_limit_interval_ms_) {
		args.push_back("--down-limit");
		args.push_back(std::to_string(down_limit_bytes_));
		args.push_back("--down-interval");
		args.push_back(std::to_string(down_limit_interval_ms_));
	}

	if (!auth_connect_dst_.empty()) {
		args.push_back("--socks5-dst-cauth");
		args.push_back(auth_connect_dst_);
	}

	printf("Starting socks5 proxy to %s (bind to %u)\n", uri_.c_str(), port_);
	proc_.start();
	if (!proc_.exit_code_)
		started_at_ = time(nullptr);
}

json proxy::to_json(void)
{
	return  {
		{ "type", type_ },
		{ "uri", uri_ },
		{ "auth_connect_dst", auth_connect_dst_ },
		{ "expired_at", expired_at_ },
		{ "started_at", started_at_ },
		{ "port", port_ },
		{ "up_limit_bytes", up_limit_bytes_ },
		{ "up_limit_interval_ms", up_limit_interval_ms_ },
		{ "down_limit_bytes", down_limit_bytes_ },
		{ "down_limit_interval_ms", down_limit_interval_ms_ },
		{ "id", id_ },
		{ "proc", proc_.to_json() }
	};
}

void proxy::from_json(const json &j)
{
	type_ = j["type"];
	uri_ = j["uri"];
	auth_connect_dst_ = j["auth_connect_dst"];
	expired_at_ = j["expired_at"];
	started_at_ = j["started_at"];
	port_ = j["port"];
	id_ = j["id"];
	proc_.from_json(j["proc"]);
}

void proxy::to_file(const std::string &path)
{
	json j = to_json();
	FILE *f;

	f = fopen(path.c_str(), "wb");
	if (!f)
		throw std::runtime_error("Failed to open file: " + path + ": " + strerror(errno));

	fprintf(f, "%s\n", j.dump(4).c_str());
	fclose(f);
}

void proxy::from_file(const std::string &path)
{
	std::string buf;
	FILE *f;

	f = fopen(path.c_str(), "rb");
	if (!f)
		throw std::runtime_error("Failed to open file: " + path + ": " + strerror(errno));

	try {
		while (1) {
			char tmp[4096];

			if (!fgets(tmp, sizeof(tmp), f))
				break;

			buf += tmp;
		}
		fclose(f);
	} catch (...) {
		fclose(f);
		throw;
	}

	from_json(json::parse(buf));
}

proxmaster::proxmaster(const std::string &storage_dir,
		       const std::string &blacklist_file,
		       const std::string &socks5_bin_file):
	storage_dir_(storage_dir),
	blacklist_file_(blacklist_file),
	socks5_bin_file_(socks5_bin_file),
	last_id_(0)
{
	std::string proxies_dir = storage_dir_ + "/proxies";
	std::string last_id_file = storage_dir_ + "/last_id.txt";

	srand(time(nullptr));
	if (!mkdir_recursive(proxies_dir.c_str()))
		throw std::runtime_error("Failed to create proxies directory: " + proxies_dir);

	f_last_id_ = fopen(last_id_file.c_str(), "rb+");
	if (!f_last_id_)
		f_last_id_ = fopen(last_id_file.c_str(), "w+");

	if (!f_last_id_)
		throw std::runtime_error("Failed to open last_id file: " + last_id_file + ": " + strerror(errno));

	fscanf(f_last_id_, "%llu", &last_id_);

	try {
		load_blacklist();
		load_proxies();
		reaper_thread_ = std::thread([this] { reaper(); });
	} catch (...) {
		fclose(f_last_id_);
		throw;
	}
}

proxmaster::~proxmaster(void)
{
	save_proxies();
	fclose(f_last_id_);

	std::lock_guard<std::mutex> lock(lock_);
	reaper_stop_ = true;
	reaper_cv_.notify_all();
	reaper_thread_.join();
}

inline void proxmaster::load_blacklist(void)
{
	if (blacklist_file_.empty())
		return;

	FILE *p = fopen(blacklist_file_.c_str(), "rb");
	char buf[512];

	if (!p)
		throw std::runtime_error("Failed to open blacklist file: " + blacklist_file_ + ": " + strerror(errno));

	while (fgets(buf, sizeof(buf), p)) {
		if (buf[0] == '\0' || buf[0] == '\n')
			continue;

		buf[strlen(buf) - 1] = '\0';
		blacklist_.push_back(buf);
	}
	fclose(p);
}

inline void proxmaster::delete_proxy_file(unsigned long long id)
{
	std::string path = storage_dir_ + "/proxies/";
	char buf[64];

	snprintf(buf, sizeof(buf), "%016llu.json", id);
	path += buf;

	remove(path.c_str());
}

inline void proxmaster::load_proxies(void)
{
	std::string path, proxies_dir = storage_dir_ + "/proxies";
	struct dirent *de;
	proxy p;
	DIR *d;

	d = opendir(proxies_dir.c_str());
	if (!d)
		throw std::runtime_error("Failed to open proxies directory: " + proxies_dir + ": " + strerror(errno));

	flock(fileno(f_last_id_), LOCK_EX);
	while (1) {
		size_t len;

		de = readdir(d);
		if (!de)
			break;

		if (de->d_name[0] == '.')
			continue;

		/* Only take files that end with .json */
		len = strlen(de->d_name);
		if (len < 5 || strcmp(de->d_name + len - 5, ".json"))
			continue;

		path = proxies_dir + "/" + de->d_name;
		if (!is_file(path.c_str()))
			continue;

		p.from_file(path);

		if (p.expired_at_ && p.expired_at_ < time(nullptr)) {
			printf("Proxy %llu expired\n", p.id_);
			delete_proxy_file(p.id_);
			continue;
		}

		p.start(socks5_bin_file_);
		proxies_.push_back(p);
	}
	closedir(d);
	flock(fileno(f_last_id_), LOCK_UN);
}

inline void proxmaster::save_proxies(void)
{
	std::string path, proxies_dir = storage_dir_ + "/proxies";
	char buf[64];

	flock(fileno(f_last_id_), LOCK_EX);
	for (auto &p : proxies_) {
		snprintf(buf, sizeof(buf), "%016llu.json", p.id_);
		path = proxies_dir + "/" + buf;
		p.to_file(path);
	}
	flock(fileno(f_last_id_), LOCK_UN);
}

inline void proxmaster::start_proxies(void)
{
	for (auto &p : proxies_)
		p.start(socks5_bin_file_);
}

inline void proxmaster::save_last_id(void)
{
	flock(fileno(f_last_id_), LOCK_EX);
	rewind(f_last_id_);
	ftruncate64(fileno(f_last_id_), 0);
	fprintf(f_last_id_, "%llu\n", last_id_);
	fflush(f_last_id_);
	flock(fileno(f_last_id_), LOCK_UN);
}

json proxmaster::get_proxy_list(void)
{
	json j = json::array();

	for (auto &p : proxies_)
		j.push_back(p.to_json());

	return j;
}

std::string gen_auth_conn_dst(void)
{
	char buf[128];

	snprintf(buf, sizeof(buf), "10.55.%d.%d", 1 + (rand() % 254), 1 + (rand() % 254));
	return buf;
}

unsigned long long proxmaster::add_proxy(const proxy &p)
{
	struct proxy p2 = p;
	std::lock_guard<std::mutex> lock(lock_);

	p2.id_ = ++last_id_;
	proxies_.push_back(p2);
	save_last_id();
	save_proxies();
	reaper_cv_.notify_all();
	return p2.id_;
}

void proxmaster::__stop_proxy(proxy &p)
{
	p.stop();
	delete_proxy_file(p.id_);
}

void proxmaster::stop_proxy(unsigned long long id)
{
	std::lock_guard<std::mutex> lock(lock_);
	size_t i;

	for (i = 0; i < proxies_.size(); i++) {
		if (proxies_[i].id_ != id)
			continue;

		__stop_proxy(proxies_[i]);
		proxies_.erase(proxies_.begin() + i);
		save_proxies();
		break;
	}

	reaper_cv_.notify_all();
}

inline void proxmaster::reaper(void)
{
	std::unique_lock<std::mutex> lock(lock_);
	int64_t min_to_exp = 1000000;
	bool got_a_stop;
	size_t i;

	while (!reaper_stop_) {

		got_a_stop = false;
		for (i = 0; i < proxies_.size(); i++) {
			proxy &p = proxies_[i];
			int64_t to_exp;

			if (p.proc_.exit_code_) {
				printf("Proxy %llu exited with code %d\n", p.id_, p.proc_.exit_code_);
				p.stop();
			}
			
			if (!p.expired_at_)
				continue;

			to_exp = p.expired_at_ - time(nullptr);

			if (to_exp <= 0) {
				printf("Proxy %llu expired\n", p.id_);
				__stop_proxy(p);
				proxies_.erase(proxies_.begin() + i);
				save_proxies();
				got_a_stop = true;
				break;
			} else if (to_exp < min_to_exp && to_exp > 0) {
				min_to_exp = to_exp;
			}
		}

		if (!got_a_stop)
			min_to_exp = 1;

		reaper_cv_.wait_for(lock, std::chrono::seconds(min_to_exp));
	}

	for (auto &p : proxies_)
		p.stop();
}
