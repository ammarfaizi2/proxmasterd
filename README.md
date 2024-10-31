
# How to run the server
```sh
PM_AUTH_TOKEN=ABC123 ./proxmasterd \
    --socks5-bin-file=/tmp/socks52socks5 \
    --storage-dir=/tmp/proxmasterd \
    --plain-port=2080 \
    --ssl-port=2443 \
    --ssl-cert-file=/tmp/cert.pem \
    --ssl-key-file=/tmp/key.key
```

`PM_AUTH_TOKEN` is an environment variable used to authenticate requests via the
`Authorization` header. Based on the above example, the client must provide a
header `Authorization: Bearer ABC123` when making requests to the server.

`PM_AUTH_TOKEN` is optional. If not provided, the server will not require
authentication.

- `--socks5-bin-file` is the path to the socks52socks5 binary.
- `--storage-dir` is the directory to store the proxy data. If the directory
  does not exist, it will be created.
- `--plain-port` is the port to listen for plain HTTP requests.
- `--ssl-port` is the port to listen for HTTPS requests.
- `--ssl-cert-file` is the path to the SSL certificate file.
- `--ssl-key-file` is the path to the SSL key file.

You must at least provide one of `--plain-port` or `--ssl-port`. If you provide
both, the server will listen on both ports. The `--ssl-port` requires the
`--ssl-cert-file` and `--ssl-key-file` options to be provided.

# Available Routes:
1) <a href="#1-get-apiv1proxylist-list-all-proxies">GET: /api/v1/proxy/list (List all proxies)</a>
2) <a href="#2-post-apiv1proxystart-start-a-new-proxy">POST: /api/v1/proxy/start (Start a new proxy)</a>
3) <a href="#3-post-apiv1proxystop-stop-a-proxy">POST: /api/v1/proxy/stop (Stop a proxy)</a>

# 1) GET: /api/v1/proxy/list (List all proxies)

Curl example:
```sh
curl -vk https://127.0.0.1:2443/api/v1/proxy/list -H "Authorization: Bearer ABC123"
```

Response example:
```json
{
    "data": [
        {
            "auth_connect_dst": "10.55.132.211",
            "down_limit_bytes": 0,
            "down_limit_interval_ms": 0,
            "expired_at": 1728526218,
            "id": 3,
            "port": 4444,
            "proc": {
                "args": ["/tmp/socks52socks5", "--workers", "4", "--bind", "0.0.0.0:4444", "--as-socks5", "--to-socks5", "socks5://user:pass@127.0.0.1:5555", "--socks5-dst-cauth", "10.55.132.211"],
                "err_output": "",
                "exit_code": 0,
                "pid": 865778
            },
            "started_at": 1728525918,
            "type": 0,
            "up_limit_bytes": 0,
            "up_limit_interval_ms": 0,
            "uri": "socks5://user:pass@127.0.0.1:5555"
        },
        {
            "auth_connect_dst": "10.55.247.55",
            "down_limit_bytes": 0,
            "down_limit_interval_ms": 0,
            "expired_at": 1728526225,
            "id": 4,
            "port": 1444,
            "proc": {
                "args": ["/tmp/socks52socks5", "--workers", "4", "--bind", "0.0.0.0:1444", "--as-socks5", "--to-socks5", "socks5://user:pass@127.0.0.1:5555", "--socks5-dst-cauth", "10.55.247.55"],
                "err_output": "",
                "exit_code": 0,
                "pid": 865896
            },
            "started_at": 1728525925,
            "type": 0,
            "up_limit_bytes": 0,
            "up_limit_interval_ms": 0,
            "uri": "socks5://user:pass@127.0.0.1:5555"
        }
    ],
    "status": 200
}
```

# 2) POST: /api/v1/proxy/start (Start a new proxy)

Curl Example:
```sh
curl -vk https://127.0.0.1:2443/api/v1/proxy/start \
  -H "Authorization: Bearer ABC123" \
  -H "Content-Type: application/json" \
  -X POST --data \
'{
    "proxy": "socks5://user:pass@127.0.0.1:5555",
    "lifetime": 300,
    "port": 1444,
    "down_limit_bytes": 3000000,
    "down_limit_interval_ms": 1000,
    "up_limit_bytes": 3000000,
    "up_limit_interval_ms": 1000
}'
```

Required fields:
- `proxy` is the URI of the socks5 proxy to forward to.
- `lifetime` is the number of seconds the proxy will be active. Set to 0 for unlimited.
- `port` is the port to bind the proxy to.

Optional fields:
- `down_limit_bytes` is the download limit in bytes.
- `down_limit_interval_ms` is the download limit interval in milliseconds.
- `up_limit_bytes` is the upload limit in bytes.
- `up_limit_interval_ms` is the upload limit interval in milliseconds.

Response examples:

**Success:**
```json
{
    "data": {
        "auth_connect_dst": "10.55.5.38",
        "down_limit_bytes": 3000000,
        "down_limit_interval_ms": 1000,
        "expired_at": 1728527623,
        "id": 6,
        "port": 1444,
        "proc": {
            "args": ["/tmp/socks52socks5", "--workers", "4", "--bind", "0.0.0.0:1444", "--as-socks5", "--to-socks5", "socks5://user:pass@127.0.0.1:5555", "--up-limit", "3000000", "--up-interval", "1000", "--down-limit", "3000000", "--down-interval", "1000", "--socks5-dst-cauth", "10.55.5.38"],
            "err_output": "",
            "exit_code": 0,
            "pid": 913069
        },
        "started_at": 1728527323,
        "type": 0,
        "up_limit_bytes": 3000000,
        "up_limit_interval_ms": 1000,
        "uri": "socks5://user:pass@127.0.0.1:5555"
    },
    "status": 200
}
```

Key points:
- `id` is the unique identifier of the proxy.
- `auth_connect_dst` is the destination IP address to authenticate with.
- `expired_at` is the Unix timestamp when the proxy will expire.

**Failure**
```json
{
    "data": {
        "cmd_args": ["/tmp/socks52socks5", "--workers", "4", "--bind", "0.0.0.0:1444", "--as-socks5", "--to-socks5", "socks5://user:pass@127.0.0.1:5555", "--up-limit", "3000000", "--up-interval", "1000", "--down-limit", "3000000", "--down-interval", "1000", "--socks5-dst-cauth", "10.55.205.40"],
        "cmd_exit_code": 158,
        "cmd_output": "[00913759] info: Forwarding via SOCKS5 proxy at socks5://user:pass@127.0.0.1:5555\n[00913759] info: SOCKS5 proxy destination connect for auth: 10.55.205.40\n[00913759] perr: Failed to bind socket: Address already in use\n",
        "error": "Failed to start proxy"
    },
    "status": 400
}
```


# 3) POST: /api/v1/proxy/stop (Stop a proxy)

Curl Example:
```sh
curl -vk https://127.0.0.1:2443/api/v1/proxy/stop \
  -H "Authorization: Bearer ABC123" \
  -H "Content-Type: application/json" \
  -X POST --data '{"id": 6}'
```

Required fields:
- `id` is the unique identifier of the proxy to stop.

Response examples:

**Success:**
```json
{
    "data": "Proxy stopped",
    "status": 200
}
```

**Failure**
```json
{
    "data": {
        "error": "Failed to stop proxy, ID is not found",
        "id": 7
    },
    "status": 400
}
```

# 4) POST: /api/v1/proxy/quota_cmd (Control the quota of a proxy)

Curl Example:
```sh
curl -vk https://127.0.0.1:2443/api/v1/proxy/quota_cmd \
  -H "Authorization: Bearer ABC123" \
  -H "Content-Type: application/json" \
  -X POST --data \
'{
    "cmd": "get",
    "id": 10061,
    "arg": 0
}'
```

- The field 'id' is the unique identifier of the proxy mentioned in the `/api/v1/proxy/list` response.

- The field 'cmd' is the command to execute.

Available 'cmd' values:
  - get: Get the current quota of the proxy.
  - set: Set the quota of the proxy.
  - add: Add to the quota of the proxy.
  - sub: Subtract from the quota of the proxy.
  - disable: Disable the quota of the proxy.
  - enable: Enable the quota of the proxy.

- The field 'arg' is the value to set, add, or subtract from the quota. The unit is in bytes.

Request examples:

1. 'add'
```json
{
    "cmd": "add",
    "id": 10061,
    "arg": 1000000
}
```
This will add 1000000 bytes (~1MB) to the quota of the proxy with ID 10061.

2. 'set'
```json
{
    "cmd": "set",
    "id": 10061,
    "arg": 1000000000
}
```
This will set the quota of the proxy with ID 10061 to 1000000000 bytes (~1GB).

3. 'get'
```json
{
    "cmd": "get",
    "id": 10061,
    "arg": 0
}
```
This is to get the current quota of the proxy with ID 10061.

4. 'sub'
```json
{
    "cmd": "sub",
    "id": 10061,
    "arg": 1000000
}
```
This will subtract 1000000 bytes (~1MB) from the quota of the proxy with ID 10061.

5. 'disable'
```json
{
    "cmd": "disable",
    "id": 10061,
    "arg": 0
}
```
This will disable the quota of the proxy with ID 10061. That also means the quota is unlimited (or not accounted for).


6. 'enable'
```json
{
    "cmd": "enable",
    "id": 10061,
    "arg": 0
}
```
This will enable the quota of the proxy with ID 10061.


Response example (taken from 'set' command):
```json
{
    "data": {
        "cmd_info": {
            "arg": 1000000000,
            "cmd": "set",
            "res": {
                "enabled": true,
                "exceeded": false,
                "quota": 1000000000,
                "quota_before_cmd": 12
            }
        },
        "proxy": {
            "auth_connect_dst": "10.55.177.144",
            "down_limit_bytes": 3000000,
            "down_limit_interval_ms": 1000,
            "expired_at": 0,
            "id": 10061,
            "port": 8551,
            "proc": {
                "args": ["./socks52socks5", "--workers", "4", "--bind", "0.0.0.0:8551", "--as-socks5", "--to-socks5", "socks5://user:pass@127.0.0.1:5555", "--quota-unix-sock", "./storage/unix_socks/p1730334488_244258292.sock", "--init-quota-size", "12", "--up-limit", "3000000", "--up-interval", "1000", "--down-limit", "3000000", "--down-interval", "1000", "--socks5-dst-cauth", "10.55.177.144"],
                "err_output": "",
                "exit_code": 0,
                "pid": 589789
            },
            "quota": 1000000000,
            "quota_enabled": true,
            "quota_exceeded": false,
            "started_at": 1730334488,
            "type": 0,
            "up_limit_bytes": 3000000,
            "up_limit_interval_ms": 1000,
            "uri": "socks5://user:pass@127.0.0.1:5555"
        }
    },
    "status": 400
}
```