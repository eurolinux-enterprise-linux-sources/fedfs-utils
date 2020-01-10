/**
 * @file src/libadmin/junction.c
 * @brief Handle junction-related ADMIN RPC operations
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
 * Unmarshal a UUID
 *
 * @param uuid UUID in packed wire format
 * @return NUL-terminated C string containing a text UUID
 */
__attribute_malloc__
static char *
admin_get_uuid(FedFsUuid uuid)
{
	char buf[FEDFS_UUID_STRLEN];
	uuid_t uu;

	memcpy(uu, uuid, sizeof(uu));
	uuid_unparse(uu, buf);
	return strdup(buf);
}

/**
 * Allocate an in-memory FSN data structure
 *
 * @return a freshly allocated FSN, or NULL
 */
__attribute_malloc__
static struct admin_fsn *
admin_new_fsn(void)
{
	return calloc(1, sizeof(struct admin_fsn));
}

/**
 * Free an in-memory FSN data structure
 *
 * @param fsn FSN to free
 */
void
admin_free_fsn(struct admin_fsn *fsn)
{
	if (fsn == NULL)
		return;

	free((void *)fsn->af_nsdb.an_hostname);
	free((void *)fsn->af_uuid);
	free(fsn);
}

/**
 * Dig returned FSN out of lookup results
 *
 * @param result RPC lookup results
 * @param fsn OUT: in-memory FSN structure
 * @return zero or an errno
 *
 * The caller must free "fsn" with admin_free_fsn().
 */
static int
admin_set_fsn(FedFsFsn result, struct admin_fsn **fsn)
{
	struct admin_fsn *new;

	new = admin_new_fsn();
	if (new == NULL)
		return ENOMEM;

	new->af_uuid = admin_get_uuid(result.fsnUuid);
	if (new->af_uuid == NULL) {
		admin_free_fsn(new);
		return ENOMEM;
	}

	if (result.nsdbName.hostname.utf8string_val == NULL ||
	    result.nsdbName.hostname.utf8string_len == 0)
		goto out;

	new->af_nsdb.an_hostname =
		strndup(result.nsdbName.hostname.utf8string_val,
			result.nsdbName.hostname.utf8string_len);
	if (new->af_nsdb.an_hostname == NULL) {
		admin_free_fsn(new);
		return ENOMEM;
	}
	new->af_nsdb.an_port = result.nsdbName.port;

out:
	*fsn = new;
	return 0;
}

/**
 * Allocate an in-memory FSL data structure
 *
 * @return a freshly allocated FSL, or NULL
 */
__attribute_malloc__
static struct admin_fsl *
admin_new_fsl(void)
{
	return calloc(1, sizeof(struct admin_fsl));
}

/**
 * Free one in-memory FSL data structure
 *
 * @param fsl FSL to free
 */
static void
admin_free_fsl(struct admin_fsl *fsl)
{
	if (fsl == NULL)
		return;

	nsdb_free_string_array((char **)fsl->al_pathname);
	free((void *)fsl->al_hostname);
	free((void *)fsl->al_uuid);
	free(fsl);
}

/**
 * Free a list of in-memory FSL data structures
 *
 * @param fsls FSL list to free
 */
void
admin_free_fsls(struct admin_fsl *fsls)
{
	struct admin_fsl *fsl;

	while (fsls != NULL) {
		fsl = fsls;
		fsls = fsl->al_next;
		admin_free_fsl(fsl);
	}
}

/**
 * Materialize one NFS FSL and link it onto the list
 *
 * @param result one NFS FSL in the result
 * @param fsls OUT: list of in-memory FSL structures
 * @return zero or an errno
 */
static int
admin_add_nfsfsl(FedFsNfsFsl result, struct admin_fsl **fsls)
{
	struct admin_fsl *new = NULL;
	int retval;

	retval = ENAMETOOLONG;
	if (result.hostname.utf8string_val == NULL ||
	    result.hostname.utf8string_len == 0)
		goto out_err;

	retval = ENOMEM;
	new = admin_new_fsl();
	if (new == NULL)
		goto out_err;

	new->al_uuid = admin_get_uuid(result.fslUuid);
	if (new->al_uuid == NULL)
		goto out_err;

	new->al_hostname = strndup(result.hostname.utf8string_val,
				   result.hostname.utf8string_len);
	if (new->al_hostname == NULL)
		goto out_err;
	new->al_port = result.port;

	retval = ENAMETOOLONG;
	if (nsdb_fedfspathname_to_path_array(result.path,
					(char ***)&new->al_pathname) != FEDFS_OK)
		goto out_err;

	new->al_next = *fsls;
	*fsls = new;
	return 0;

out_err:
	admin_free_fsl(new);
	return retval;
}

/**
 * Materialize one FSL and link it onto the list
 *
 * @param results one FSL in the result
 * @param fsls OUT: list of in-memory FSL structures
 * @return zero or an errno
 */
static int
admin_add_fsl(FedFsFsl results, struct admin_fsl **fsls)
{
	switch (results.type) {
	case FEDFS_NFS_FSL:
		return admin_add_nfsfsl(results.FedFsFsl_u.nfsFsl, fsls);
	default:
		return 0;
	}
}

/**
 * Dig returned FSLs out of lookup results
 *
 * @param results RPC lookup results
 * @param fsls OUT: list of in-memory FSL structures
 * @return zero or an errno
 *
 * The caller must free "fsls" with admin_free_fsls().
 */
static int
admin_set_fsls(FedFsLookupResOk results, struct admin_fsl **fsls)
{
	struct admin_fsl *new = NULL;
	int retval = 0;
	u_int i;

	for (i = 0; i < results.fsl.fsl_len && retval == 0; i++)
		retval = admin_add_fsl(results.fsl.fsl_val[i], &new);

	*fsls = new;
	return retval;
}

/**
 * Create a junction or replication on a remote fileserver
 *
 * @param host an initialized and opened admin_t
 * @param procedure RPC procedure to call
 * @param arg call arguments
 * @return zero or an errno
 */
static int
admin_create_rpc(admin_t host, rpcproc_t procedure, FedFsCreateArgs *arg)
{
	FedFsStatus result;
	unsigned int delay;

	delay = FEDFS_DELAY_MIN_SECS;
	do {
		xlog(D_CALL, "sending CREATE to %s",
			admin_hostname(host));

		memset((char *)&result, 0, sizeof(result));
		host->ad_rpc_status = clnt_call(host->ad_client, procedure,
				(xdrproc_t)xdr_FedFsCreateArgs,
				(caddr_t)arg,
				(xdrproc_t)xdr_FedFsStatus, (caddr_t)&result,
				host->ad_timeout);

		xlog(D_CALL, "RPC CREATE returned %d",
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
 * Create a junction or replication on a remote fileserver
 *
 * @param host an initialized admin_t
 * @param procedure RPC procedure to call
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn FileSet Name to set
 * @return zero or an errno
 */
static int
admin_create_call(admin_t host, rpcproc_t procedure,
		char * const *path_array, struct admin_fsn *fsn)
{
	FedFsCreateArgs arg;
	int retval;
	uuid_t uu;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (path_array == NULL || fsn == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	if (uuid_parse(fsn->af_uuid, uu) != 0)
		return EINVAL;
	memcpy(arg.fsn.fsnUuid, uu, sizeof(FedFsUuid));
	arg.fsn.nsdbName.hostname.utf8string_len =
					strlen(fsn->af_nsdb.an_hostname);
	arg.fsn.nsdbName.hostname.utf8string_val =
					(char *)fsn->af_nsdb.an_hostname;
	arg.fsn.nsdbName.port = fsn->af_nsdb.an_port;

	arg.path.type = FEDFS_PATH_SYS;
	if (nsdb_path_array_to_fedfspathname(path_array,
				&arg.path.FedFsPath_u.adminPath) != FEDFS_OK)
		return ENAMETOOLONG;

	retval = admin_create_rpc(host, procedure, &arg);

	nsdb_free_fedfspathname(&arg.path.FedFsPath_u.adminPath);
	return retval;
}

/**
 * Delete a junction or replication on a remote fileserver
 *
 * @param host an initialized and opened admin_t
 * @param procedure RPC procedure to call
 * @param arg call arguments
 * @return zero or an errno
 */
static int
admin_delete_rpc(admin_t host, rpcproc_t procedure, FedFsPath *arg)
{
	FedFsStatus result;
	unsigned int delay;

	delay = FEDFS_DELAY_MIN_SECS;
	do {
		xlog(D_CALL, "sending DELETE to %s",
			admin_hostname(host));

		memset((char *)&result, 0, sizeof(result));
		host->ad_rpc_status = clnt_call(host->ad_client, procedure,
				(xdrproc_t)xdr_FedFsPath, (caddr_t)arg,
				(xdrproc_t)xdr_FedFsStatus, (caddr_t)&result,
				host->ad_timeout);

		xlog(D_CALL, "RPC DELETE returned %d",
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
 * Delete a junction or replication on a remote fileserver
 *
 * @param host an initialized admin_t
 * @param procedure RPC procedure to call
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @return zero or an errno
 */
static int
admin_delete_call(admin_t host, rpcproc_t procedure,
		char * const *path_array)
{
	FedFsPath arg;
	int retval;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (path_array == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	if (nsdb_path_array_to_fedfspathname(path_array,
					&arg.FedFsPath_u.adminPath) != FEDFS_OK)
		return ENAMETOOLONG;

	retval = admin_delete_rpc(host, procedure, &arg);

	nsdb_free_fedfspathname(&arg.FedFsPath_u.adminPath);
	return retval;
}

/**
 * Request FSN stored in a remote junction
 *
 * @param host an initialized and opened admin_t
 * @param procedure RPC procedure to call
 * @param arg call arguments
 * @param result OUT: call results (filled-in)
 * @return zero or an errno
 */
static int
admin_lookup_rpc(admin_t host, rpcproc_t procedure,
		FedFsLookupArgs *arg, FedFsLookupRes *result)
{
	unsigned int delay;

	delay = FEDFS_DELAY_MIN_SECS;
	do {
		xlog(D_CALL, "sending LOOKUP to %s",
			admin_hostname(host));

		memset((char *)result, 0, sizeof(*result));
		host->ad_rpc_status = clnt_call(host->ad_client,
				procedure,
				(xdrproc_t)xdr_FedFsLookupArgs, (caddr_t)arg,
				(xdrproc_t)xdr_FedFsLookupRes, (caddr_t)result,
				host->ad_timeout);

		xlog(D_CALL, "RPC DELETE returned %d",
			host->ad_rpc_status);

		if (host->ad_rpc_status == RPC_AUTHERROR)
			return EACCES;
		if (host->ad_rpc_status != RPC_SUCCESS)
			return EIO;

		if (result->status != FEDFS_ERR_DELAY)
			break;

		clnt_freeres(host->ad_client,
			(xdrproc_t)xdr_FedFsLookupRes, (caddr_t)result);
		(void)sleep(delay);
		delay = fedfs_delay(delay);
	} while (1);

	host->ad_srv_status = result->status;
	return 0;
}

/**
 * Request FSN stored in a remote junction
 *
 * @param host an initialized admin_t
 * @param procedure RPC procedure to call
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @return zero or an errno
 *
 * The caller must free "fsn" with admin_free_fsn().
 */
static int
admin_lookup_none_call(admin_t host, rpcproc_t procedure,
		char * const *path_array, struct admin_fsn **fsn)
{
	FedFsLookupRes result;
	FedFsLookupArgs arg;
	int retval;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (path_array == NULL || fsn == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	arg.resolve = FEDFS_RESOLVE_NONE;
	arg.path.type = FEDFS_PATH_SYS;
	if (nsdb_path_array_to_fedfspathname(path_array,
				&arg.path.FedFsPath_u.adminPath) != FEDFS_OK)
		return ENAMETOOLONG;

	retval = admin_lookup_rpc(host, procedure, &arg, &result);

	nsdb_free_fedfspathname(&arg.path.FedFsPath_u.adminPath);

	if (retval == 0 && result.status == FEDFS_OK)
		retval = admin_set_fsn(result.FedFsLookupRes_u.resok.fsn, fsn);

	clnt_freeres(host->ad_client,
			(xdrproc_t)xdr_FedFsLookupRes, (caddr_t)&result);
	return retval;
}

/**
 * Request FSN stored in a remote junction and FSLs that FSN resolves to
 *
 * @param host an initialized admin_t
 * @param procedure RPC procedure to call
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param type whether to perturb the server's FSL cache
 * @param fsn OUT: the FSN stored in the requested junction
 * @param fsls OUT: list of FSLs cached on the fileserver
 * @return zero or an errno
 *
 * The caller must free "fsn" with admin_free_fsn().  The caller must
 * free "fsls" with admin_free_fsls().
 */
static int
admin_lookup_typed_call(admin_t host, rpcproc_t procedure,
		char * const *path_array, FedFsResolveType type,
		struct admin_fsn **fsn, struct admin_fsl **fsls)
{
	struct admin_fsn *tmp_fsn;
	struct admin_fsl *tmp_fsls;
	FedFsLookupRes result;
	FedFsLookupArgs arg;
	int retval;

	if (host == NULL)
		return EINVAL;
	admin_reset(host);

	if (path_array == NULL || fsn == NULL || fsls == NULL)
		return EINVAL;

	if (!admin_is_connected(host))
		return ENOTCONN;

	memset(&arg, 0, sizeof(arg));
	arg.resolve = type;
	arg.path.type = FEDFS_PATH_SYS;
	if (nsdb_path_array_to_fedfspathname(path_array,
				&arg.path.FedFsPath_u.adminPath) != FEDFS_OK)
		return ENAMETOOLONG;

	retval = admin_lookup_rpc(host, procedure, &arg, &result);

	nsdb_free_fedfspathname(&arg.path.FedFsPath_u.adminPath);

	if (retval != 0)
		goto out;

	switch (result.status) {
	case FEDFS_OK:
		retval = admin_set_fsn(result.FedFsLookupRes_u.resok.fsn, &tmp_fsn);
		if (retval != 0)
			break;

		retval = admin_set_fsls(result.FedFsLookupRes_u.resok, &tmp_fsls);
		if (retval != 0) {
			admin_free_fsn(tmp_fsn);
			break;
		}

		*fsn = tmp_fsn;
		*fsls = tmp_fsls;
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		host->ad_ldaperr = result.FedFsLookupRes_u.ldapResultCode;
		break;
	default:
		break;
	}

out:
	clnt_freeres(host->ad_client,
			(xdrproc_t)xdr_FedFsLookupRes, (caddr_t)&result);
	return retval;
}

/**
 * FEDFS_CREATE_JUNCTION (5.2) - Create a junction on a remote fileserver
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn FileSet Name to set
 * @return zero or an errno
 */
int
admin_create_junction(admin_t host, char * const *path_array,
		struct admin_fsn *fsn)
{
	return admin_create_call(host, FEDFS_CREATE_JUNCTION,
					path_array, fsn);
}

/**
 * FEDFS_DELETE_JUNCTION (5.3) - Delete a junction on a remote fileserver
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @return zero or an errno
 */
int
admin_delete_junction(admin_t host, char * const *path_array)
{
	return admin_delete_call(host, FEDFS_DELETE_JUNCTION,
					path_array);
}

/**
 * FEDFS_LOOKUP_JUNCTION (5.4) - Request FSN stored in a remote junction
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @return zero or an errno
 *
 * The caller must free "fsn" with admin_free_fsn().
 */
int
admin_lookup_junction_none(admin_t host, char * const *path_array,
		struct admin_fsn **fsn)
{
	return admin_lookup_none_call(host, FEDFS_LOOKUP_JUNCTION,
					path_array, fsn);
}

/**
 * FEDFS_LOOKUP_JUNCTION (5.4) - Request FSLs cached by remote server
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @param fsls OUT: list of FSLs cached on the fileserver
 * @return zero or an errno
 *
 * The fileserver does not perform FSN resolution unless it hasn't
 * already done so.
 *
 * The caller must free "fsn" with admin_free_fsn().  The caller must
 * free "fsls" with admin_free_fsls().
 */
int
admin_lookup_junction_cached(admin_t host, char * const *path_array,
		struct admin_fsn **fsn, struct admin_fsl **fsls)
{
	return admin_lookup_typed_call(host, FEDFS_LOOKUP_JUNCTION,
					path_array, FEDFS_RESOLVE_CACHE,
					fsn, fsls);
}

/**
 * FEDFS_LOOKUP_JUNCTION (5.4) - Request FSLs from NSDB via remote server
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @param fsls OUT: list of FSLs cached on the fileserver
 * @return zero or an errno
 *
 * The fileserver performs a fresh FSN resolution and renews its
 * FSL cache before returning.
 *
 * The caller must free "fsn" with admin_free_fsn().  The caller must
 * free "fsls" with admin_free_fsls().
 */
int
admin_lookup_junction_nsdb(admin_t host, char * const *path_array,
		struct admin_fsn **fsn, struct admin_fsl **fsls)
{
	return admin_lookup_typed_call(host, FEDFS_LOOKUP_JUNCTION,
					path_array, FEDFS_RESOLVE_NSDB,
					fsn, fsls);
}

/**
 * FEDFS_CREATE_REPLICATION (5.5)
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn FileSet Name to set
 * @return zero or an errno
 */
int
admin_create_replication(admin_t host, char * const*path_array,
		struct admin_fsn *fsn)
{
	return admin_create_call(host, FEDFS_CREATE_REPLICATION,
					path_array, fsn);
}

/**
 * FEDFS_DELETE_REPLICATION (5.6)
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @return zero or an errno
 */
int
admin_delete_replication(admin_t host, char * const*path_array)
{
	return admin_delete_call(host, FEDFS_DELETE_REPLICATION,
					path_array);
}

/**
 * FEDFS_LOOKUP_REPLICATION (5.7) - Request FSN stored in a remote replication
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @return zero or an errno
 *
 * The caller must free "fsn" with admin_free_fsn().
 */
int
admin_lookup_replication_none(admin_t host, char * const*path_array,
		struct admin_fsn **fsn)
{
	return admin_lookup_none_call(host, FEDFS_LOOKUP_REPLICATION,
					path_array, fsn);
}

/**
 * FEDFS_LOOKUP_REPLICATION (5.7) - Request FSLs cached by remote server
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @param fsls OUT: list of FSLs cached on the fileserver
 * @return zero or an errno
 *
 * The fileserver does not perform FSN resolution unless it hasn't
 * already done so.
 *
 * The caller must free "fsn" with admin_free_fsn().  The caller must
 * free "fsls" with admin_free_fsls().
 */
int
admin_lookup_replication_cached(admin_t host, char * const*path_array,
		struct admin_fsn **fsn, struct admin_fsl **fsls)
{
	return admin_lookup_typed_call(host, FEDFS_LOOKUP_REPLICATION,
					path_array, FEDFS_RESOLVE_CACHE,
					fsn, fsls);
}

/**
 * FEDFS_LOOKUP_REPLICATION (5.7)
 *
 * @param host an initialized admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param fsn OUT: the FSN stored in the requested junction
 * @param fsls OUT: list of FSLs cached on the fileserver
 * @return zero or an errno
 *
 * The fileserver performs a fresh FSN resolution and renews its
 * FSL cache before returning.
 *
 * The caller must free "fsn" with admin_free_fsn().  The caller must
 * free "fsls" with admin_free_fsls().
 */
int
admin_lookup_replication_nsdb(admin_t host, char * const*path_array,
		struct admin_fsn **fsn, struct admin_fsl **fsls)
{
	return admin_lookup_typed_call(host, FEDFS_LOOKUP_REPLICATION,
					path_array, FEDFS_RESOLVE_NSDB,
					fsn, fsls);
}
