// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__WEB_H
#define PROXMASTERD__WEB_H

#include <proxmasterd/http.h>

#ifdef __cplusplus
extern "C" {
#endif

void pm_web_handle_req(struct pm_http_req *req, struct pm_http_res *res, void *arg);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef PROXMASTERD__WEB_H */
