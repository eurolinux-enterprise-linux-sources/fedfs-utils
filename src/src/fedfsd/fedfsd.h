/*
 * @file src/fedfsd/fedfsd.h
 * @brief Common declarations for fedfsd
 */

/*
 * Copyright 2010 Oracle.  All rights reserved.
 *
 * This file is part of fedfs-utils.
 *
 * fedfs-utils is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2.0 as
 * published by the Free Software Foundation.
 *
 * fedfs-utils is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2.0 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2.0 along with fedfs-utils.  If not, see:
 *
 *	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 */

#ifndef _FEDFSD_H_
#define _FEDFSD_H_

#include <sys/types.h>

#include <stdbool.h>
#include <time.h>
#include <ldap.h>
#include <sqlite3.h>

#include <rpc/svc.h>

#include "fedfs_admin.h"

#define FEDFSD_ACCESS_CONFIG	"/etc/fedfsd/access.conf"

/*
 * auth.c
 */
_Bool		fedfsd_read_access_config(const char *pathname);

_Bool		fedfsd_auth_none(void);
_Bool		fedfsd_auth_unix(struct svc_req *rqstp);
_Bool		fedfsd_auth_rpc_gss(struct svc_req *rqstp);

/*
 * gss.c
 */
extern bool_t	fedfsd_no_dispatch;
_Bool		fedfsd_set_up_authenticators(void);
char *		fedfsd_get_gss_cred(struct svc_req *rqstp);

/*
 * listen.c
 */
void		fedfsd_svc_create(const char *name, rpcprog_t program,
				rpcvers_t version,
				void (*dispatch)(struct svc_req *, SVCXPRT *),
				const uint16_t port);

/*
 * privilege.c
 */
_Bool		fedfsd_drop_privileges(const uid_t uid, const gid_t gid);

/*
 * svc.c
 */
void		fedfsd_dispatch_1(struct svc_req *rqstp, SVCXPRT *xprt);

#endif	/* !_FEDFSD_H_ */
