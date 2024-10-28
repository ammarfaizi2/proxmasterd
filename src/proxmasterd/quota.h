// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__QUOTA_H
#define PROXMASTERD__QUOTA_H

#include <stdint.h>

enum {
	QUOTA_PKT_ADD		= 0,
	QUOTA_PKT_SUB		= 1,
	QUOTA_PKT_SET		= 2,
	QUOTA_PKT_GET		= 3,
	QUOTA_PKT_RES		= 4,
};

int qo_send_cmd(int fd, uint8_t cmd, uint64_t val, uint64_t *ret_p);
int qo_connect(const char *path);

#endif /* #ifndef PROXMASTERD__QUOTA_H */
