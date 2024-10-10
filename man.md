
# Command Examples
```sh
PM_AUTH_TOKEN=ABC123 ./proxmasterd \
    --socks5-bin-file=/tmp/socks52socks5 \
    --storage-dir=/tmp/proxmasterd \
    --plain-port=2080 \
    --ssl-port=2443 \
    --ssl-cert-file=/tmp/cert.pem \
    --ssl-key-file=/tmp/key.key
```

# Routes:
## 1) GET: /api/v1/proxy/list (List all proxies)

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

## 2) POST: /api/v1/proxy/start (Start a new proxy)

Curl Example:
```sh
curl -vk https://127.0.0.1:2443/api/v1/proxy/list \
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

Response examples:

- Success:
```json
{
    "data": {
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
    },
    "status": 200
}
```

- Failure:
```json
{
    "data": {
        "cmd_args": [ "/tmp/socks52socks5", "--workers", "4", "--bind", "0.0.0.0:1444", "--as-socks5", "--to-socks5", "socks5://user:pass@127.0.0.1:5555", "--up-limit", "3000000", "--up-interval", "1000", "--down-limit", "3000000", "--down-interval", "1000", "--socks5-dst-cauth", "10.55.1.57" ],
        "cmd_exit_code": 158,
        "cmd_output": "[00883858] info: Forwarding via SOCKS5 proxy at socks5://user:pass@127.0.0.1:5555\n[00883858] info: SOCKS5 proxy destination connect for auth: 10.55.1.57\n[00883858] perr: Failed to bind socket: Address already in use\n",
        "error": "Failed to start proxy"
    },
    "status": 400
}
```
