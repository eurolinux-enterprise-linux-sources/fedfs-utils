/*
 * @file src/libadmin/admin-internal.h
 * @brief Private declarations for the ADMIN API
 */

/*
 * Copyright 2013 Oracle.  All rights reserved.
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

#ifndef _FEDFS_ADMIN_INTERNAL_H_
#define _FEDFS_ADMIN_INTERNAL_H_

#include <time.h>
#include <rpc/clnt.h>
#include <rpc/auth_gss.h>

#include "fedfs_admin.h"
#include "admin.h"

/**
 * object that internally represents an ADMIN service
 */
struct fedfs_admin {
	char			*ad_hostname;
	char			*ad_nettype;
	int			 ad_secflavor;
	rpc_gss_svc_t		 ad_gss_svc;
	CLIENT			*ad_client;
	enum clnt_stat		 ad_rpc_status;
	struct timeval		 ad_timeout;
	FedFsStatus		 ad_srv_status;
	int			 ad_ldaperr;
};

/**
 * Reset error status values
 */
void		 admin_reset(admin_t host);

/**
 * Create an AUTH and GSS context
 */
int		 admin_authgss_create(CLIENT *clnt, admin_t host, AUTH **auth);

#endif	/* !_FEDFS_ADMIN_INTERNAL_H_ */
