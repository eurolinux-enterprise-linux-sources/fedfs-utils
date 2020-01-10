/**
 * @file src/libadmin/nsdb.c
 * @brief Handle NSDB-related ADMIN RPC operations
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

#include <sys/types.h>

#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <uuid/uuid.h>

#include "fedfs_admin.h"
#include "fedfs.h"
#include "admin-internal.h"
#include "admin.h"
#include "xlog.h"

/**
 * Set up a FedFsNsdbName argument
 *
 * @param nsdb NSDB hostname and port
 * @param arg OUT: FedFsNsdbName (filled-in)
 */
static void
admin_set_nsdb_arg(const struct admin_nsdb *nsdb, FedFsNsdbName *arg)
{
	arg->hostname.utf8string_len = strlen(nsdb->an_hostname);
	arg->hostname.utf8string_val = (char *)nsdb->an_hostname;
	arg->port = nsdb->an_port;
}

/**
 * Allocate a structure for carrying an x.509 certificate
 *
 * @return a freshly allocated admin_cert, or NULL
 */
__attribute_malloc__
static struct admin_cert *
admin_new_cert(void)
{
	return calloc(1, sizeof(struct admin_cert));
}

/**
 * Free an admin_cert
 *
 * @param cert admin_cert to free
 */
void
admin_free_cert(struct admin_cert *cert)
{
	if (cert == NULL)
		return;

	free((void *)cert->ac_data);
	free(cert);
}

/**
 * Dig returned certificate out of results
 *
 * @param result RPC results
 * @param sectype OUT: connection security for specified NSDB
 * @param cert OUT: returned x.509 certificate data in DER format
 * @return zero or an errno
 *
 * Caller must free "cert" with admin_free_cert().
 */
static int
admin_set_nsdb_secdata(FedFsGetNsdbParamsRes result,
		FedFsConnectionSec *sectype, struct admin_cert **cert)
{
	FedFsNsdbParams *params = &result.FedFsGetNsdbParamsRes_u.params;
	unsigned int len = params->FedFsNsdbParams_u.secData.secData_len;
	char *buf = params->FedFsNsdbParams_u.secData.secData_val;
	struct admin_cert *new;

	new = admin_new_cert();
	if (new == NULL)
		return ENOMEM;

	new->ac_data = malloc(len);
	if (new->ac_data == NULL) {
		free(new);
		return ENOMEM;
	}

	memcpy((void *)new->ac_data, buf, len);
	new->ac_len = len;
	*cert = new;
	*sectype = params->secType;
	return 0;
}

/**
 * Set NSDB connection parameters on a remote fileserver
 *
 * @param host an initialized and opened admin_t
 * @param arg call arguments
 * @return zero or an errno
 */
static int
admin_set_nsdb_params_rpc(admin_t host, FedFsSetNsdbParamsArgs *arg)
{
	FedFsStatus result;
	unsigned int delay;

	delay = FEDFS_DELAY_MIN_SECS;
	do {
		xlog(D_CALL, "sending SET_NSDB_PARAMS to %s",
			admin_hostname(host));

		memset((char *)&result, 0, sizeof(result));
		host->ad_rpc_status = clnt_call(host->ad_client,
			FEDFS_SET_NSDB_PARAMS,
			(xdrproc_t)xdr_FedFsSetNsdbParamsArgs, (caddr_t)arg,
			(xdrproc_t)xdr_FedFsStatus, (caddr_t)&result,
			host->ad_timeout);

		xlog(D_CALL, "RPC SET_NSDB_PARAMS returned %d",
			host->ad_rpc_status);

		if (host->ad_rpc_status == RPC_AUTHERROR)
			return EACCES;
		if (host->ad_rpc_status != RPC_SUCCESS)
			return EIO;

		if (result != FEDFS_ERR_DELAY)
			break;

		(void)sleep(delay);
		delay = fedfs_delay(delay);
	} while (1);

	host->ad_srv_status = result;
	return 0;
}

/**
 * FEDFS_SET_NSDB_PARAMS (5.8) - Set NSDB connection parameters on a remote fileserver
 *
 * @param host an initialized admin_t
 * @param nsdb hostname and port of an NSDB service
 * @return zero or an errno
 */
int
admin_set_nsdb_params_none(admin_t host, const struct admin_nsdb *nsdb)
{
	FedFsSetNsdbParamsArgs arg;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (nsdb == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	arg.params.secType = FEDFS_SEC_NONE;
	admin_set_nsdb_arg(nsdb, &arg.nsdbName);

	return admin_set_nsdb_params_rpc(host, &arg);
}

/**
 * FEDFS_SET_NSDB_PARAMS (5.8) - Set NSDB connection parameters on a remote fileserver
 *
 * @param host an initialized admin_t
 * @param nsdb hostname and port of an NSDB service
 * @param cert x.509 certificate data in DER format
 * @return zero or an errno
 */
int
admin_set_nsdb_params_tls(admin_t host, const struct admin_nsdb *nsdb,
		const struct admin_cert *cert)
{
	FedFsSetNsdbParamsArgs arg;
	int retval;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (nsdb == NULL || cert == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	arg.params.secType = FEDFS_SEC_TLS;
	arg.params.FedFsNsdbParams_u.secData.secData_len = cert->ac_len;
	arg.params.FedFsNsdbParams_u.secData.secData_val =
							(char *)cert->ac_data;
	admin_set_nsdb_arg(nsdb, &arg.nsdbName);

	retval = admin_set_nsdb_params_rpc(host, &arg);

	free(arg.params.FedFsNsdbParams_u.secData.secData_val);
	return retval;
}

/**
 * Retrieve NSDB connection parameters
 *
 * @param host an initialized and opened admin_t
 * @param arg call arguments
 * @param result call result (filled-in)
 * @return zero or an errno
 */
static int
admin_get_nsdb_params_rpc(admin_t host, FedFsNsdbName *arg,
		FedFsGetNsdbParamsRes *result)
{
	unsigned int delay;

	delay = FEDFS_DELAY_MIN_SECS;
	do {
		xlog(D_CALL, "sending GET_NSDB_PARAMS to %s",
			admin_hostname(host));

		memset((char *)result, 0, sizeof(*result));
		host->ad_rpc_status = clnt_call(host->ad_client,
			FEDFS_GET_NSDB_PARAMS,
			(xdrproc_t)xdr_FedFsNsdbName, (caddr_t)arg,
			(xdrproc_t)xdr_FedFsGetNsdbParamsRes, (caddr_t)&result,
			host->ad_timeout);

		xlog(D_CALL, "RPC GET_NSDB_PARAMS returned %d",
			host->ad_rpc_status);

		if (host->ad_rpc_status == RPC_AUTHERROR)
			return EACCES;
		if (host->ad_rpc_status != RPC_SUCCESS)
			return EIO;

		if (result->status != FEDFS_ERR_DELAY)
			break;

		clnt_freeres(host->ad_client,
				(xdrproc_t)xdr_FedFsGetNsdbParamsRes,
				(caddr_t)result);
		(void)sleep(delay);
		delay = fedfs_delay(delay);
	} while (1);

	host->ad_srv_status = result->status;
	return 0;
}

/**
 * FEDFS_GET_NSDB_PARAMS (5.9)
 *
 * @param host an initialized admin_t
 * @param nsdb hostname and port of an NSDB service
 * @param sectype OUT: connection security for specified NSDB
 * @param cert OUT: returned x.509 certificate data in DER format
 * @return zero or an errno
 *
 * Caller must free "cert" with admin_free_cert().
 */
int
admin_get_nsdb_params(admin_t host, struct admin_nsdb *nsdb,
		FedFsConnectionSec *sectype, struct admin_cert **cert)
{
	FedFsGetNsdbParamsRes result;
	FedFsNsdbName arg;
	int retval;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (nsdb == NULL || sectype == NULL || cert == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	admin_set_nsdb_arg(nsdb, &arg);

	retval = admin_get_nsdb_params_rpc(host, &arg, &result);

	if (retval == 0 && result.status == FEDFS_OK)
		retval = admin_set_nsdb_secdata(result, sectype, cert);

	clnt_freeres(host->ad_client, (xdrproc_t)xdr_FedFsGetNsdbParamsRes,
							(caddr_t)&result);
	return retval;
}

/**
 * Retrieve limited NSDB connection parameters
 *
 * @param host an initialized and opened admin_t
 * @param arg call arguments
 * @param result call result (filled-in)
 * @return zero or an errno
 */
static int
admin_get_limited_nsdb_params_rpc(admin_t host, FedFsNsdbName *arg,
		FedFsGetLimitedNsdbParamsRes *result)
{
	unsigned int delay;

	delay = FEDFS_DELAY_MIN_SECS;
	do {
		xlog(D_CALL, "sending GET_LIMITED_NSDB_PARAMS to %s",
			admin_hostname(host));

		memset((char *)result, 0, sizeof(*result));
		host->ad_rpc_status = clnt_call(host->ad_client,
			FEDFS_GET_LIMITED_NSDB_PARAMS,
			(xdrproc_t)xdr_FedFsNsdbName, (caddr_t)arg,
			(xdrproc_t)xdr_FedFsGetLimitedNsdbParamsRes,
			(caddr_t)result, host->ad_timeout);

		xlog(D_CALL, "RPC GET_LIMITED_NSDB_PARAMS returned %d",
			host->ad_rpc_status);

		if (host->ad_rpc_status == RPC_AUTHERROR)
			return EACCES;
		if (host->ad_rpc_status != RPC_SUCCESS)
			return EIO;

		if (result->status != FEDFS_ERR_DELAY)
			break;

		clnt_freeres(host->ad_client,
				(xdrproc_t)xdr_FedFsGetLimitedNsdbParamsRes,
				(caddr_t)result);
		(void)sleep(delay);
		delay = fedfs_delay(delay);
	} while (1);

	host->ad_srv_status = result->status;
	return 0;
}

/**
 * FEDFS_GET_LIMITED_NSDB_PARAMS (5.10)
 *
 * @param host an initialized admin_t
 * @param nsdb hostname and port of an NSDB service
 * @param sectype OUT: connection security for specified NSDB
 * @return zero or an errno
 */
int
admin_get_limited_nsdb_params(admin_t host, struct admin_nsdb *nsdb,
		FedFsConnectionSec *sectype)
{
	FedFsGetLimitedNsdbParamsRes result;
	FedFsNsdbName arg;
	int retval;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (nsdb == NULL || sectype == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	admin_set_nsdb_arg(nsdb, &arg);

	retval = admin_get_limited_nsdb_params_rpc(host, &arg, &result);

	if (retval == 0 && result.status == FEDFS_OK)
		*sectype = result.FedFsGetLimitedNsdbParamsRes_u.secType;

	clnt_freeres(host->ad_client,
			(xdrproc_t)xdr_FedFsGetLimitedNsdbParamsRes,
			(caddr_t)&result);
	return retval;
}
