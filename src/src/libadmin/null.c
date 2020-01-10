/**
 * @file src/libadmin/null.c
 * @brief Handle NULL ADMIN RPC operation
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

#include <unistd.h>
#include <errno.h>

#include "fedfs_admin.h"
#include "admin-internal.h"
#include "xlog.h"

/**
 * FEDFS_NULL (5.1) - Send a NULL ADMIN request (ping) to a remote fileserver
 *
 * @param host an initialized admin_t
 * @return zero or an errno
 *
 * The RPC procedure does not return a result.  We fill in a
 * status of FEDFS_OK if the RPC succeeds.
 */
int
admin_null(admin_t host)
{
	char result;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (!admin_is_connected(host))
		return ENOTCONN;

	xlog(D_CALL, "sending NULL to %s",
		admin_hostname(host));

	memset((char *)&result, 0, sizeof(result));
	host->ad_rpc_status = clnt_call(host->ad_client,
			FEDFS_NULL,
			(xdrproc_t)xdr_void, (caddr_t)NULL,
			(xdrproc_t)xdr_void, (caddr_t)&result,
			host->ad_timeout);

	xlog(D_CALL, "RPC NULL returned %d",
		host->ad_rpc_status);

	if (host->ad_rpc_status == RPC_AUTHERROR)
		return EACCES;
	if (host->ad_rpc_status != RPC_SUCCESS)
		return EIO;

	host->ad_srv_status = FEDFS_OK;
	return 0;
}
