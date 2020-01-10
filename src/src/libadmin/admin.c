/**
 * @file src/libadmin/admin.c
 * @brief Manage admin_t objects
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

#include "fedfs_admin.h"
#include "fedfs.h"
#include "admin-internal.h"
#include "admin.h"
#include "xlog.h"

/**
 * Default RPC request timeout
 */
static const struct timeval admin_rpc_timeout = { 25, 0 };

/**
 * Return admin_t's hostname
 *
 * @param host an initialized admin_t
 * @return NUL-terminated C string containing "host's" hostname
 *
 * Lifetime of this string is the same as the lifetime of the
 * admin_t.  Caller must not free this string, and must not use
 * it after the admin_t is freed.
 */
const char *admin_hostname(const admin_t host)
{
	if (host == NULL)
		return NULL;
	return host->ad_hostname;
}

/**
 * Return length of admin_t's hostname, in bytes
 *
 * @param host an initialized admin_t
 * @return the number of bytes in "host's" hostname, excluding the terminating NUL
 */
size_t admin_hostname_len(const admin_t host)
{
	if (host == NULL)
		return 0;
	return strlen(host->ad_hostname);
}

/**
 * Return admin_t's nettype
 *
 * @param host an initialized admin_t
 * @return NUL-terminated C string containing "host's" nettype
 *
 * Lifetime of this string is the same as the lifetime of the
 * admin_t.  Caller must not free this string, and must not use
 * it after the admin_t is freed.
 */
const char *admin_nettype(const admin_t host)
{
	if (host == NULL)
		return NULL;
	return host->ad_nettype;
}

/**
 * Predicate: is "host" connected to a remote ADMIN service?
 *
 * @param host an initialized admin_t struct
 * @return true if the "host" is connected
 */
_Bool
admin_is_connected(admin_t host)
{
	return host->ad_client != NULL;
}

/**
 * Create an AUTH_UNIX Auth
 *
 * @param auth OUT: a fresh AUTH object
 * @return zero or an errno
 *
 * Caller must destroy returned object with auth_destroy()
 */
static int
admin_authunix_create(AUTH **auth)
{
	AUTH *result;

	result = authunix_create_default();
	if (result == NULL) {
		xlog(D_GENERAL, "%s", clnt_spcreateerror(__func__));
		return EACCES;
	}

	*auth = result;
	return 0;
}

/**
 * Connect to a remote ADMIN service
 *
 * @param host an initialized admin_t struct
 * @return zero or an errno
 */
static int
admin_open(admin_t host)
{
	CLIENT *clnt;
	AUTH *auth;
	int err;

	if (admin_is_connected(host))
		return 0;

	xlog(D_CALL, "opening admin_t for %s",
		admin_hostname(host));

	clnt = clnt_create(admin_hostname(host),
				FEDFS_PROG, FEDFS_V1, admin_nettype(host));
	if (clnt == NULL)
		return ENOTCONN;

	switch (host->ad_secflavor) {
	case AUTH_UNIX:
		err = admin_authunix_create(&auth);
		break;
	case RPCSEC_GSS:
		err = admin_authgss_create(clnt, host, &auth);
		break;
	default:
		xlog(D_GENERAL, "%s: Unsupported security flavor", __func__);
		return EINVAL;
	}
	if (err != 0) {
		(void)clnt_destroy(clnt);
		return err;
	}

	host->ad_client = clnt;
	clnt->cl_auth = auth;
	return 0;
}

/**
 * Free TI-RPC library and network resources
 *
 * @param host an initialized admin_t struct
 */
static int
admin_close(admin_t host)
{
	if (!admin_is_connected(host))
		return ENOTCONN;

	xlog(D_CALL, "closing admin_t for %s",
		admin_hostname(host));

	auth_destroy(host->ad_client->cl_auth);
	(void)clnt_destroy(host->ad_client);
	host->ad_client = NULL;
	return 0;
}

/**
 * Release all resources associated with an admin_t object
 *
 * @param host admin_t allocated by admin_new()
 *
 * This API performs an implicit admin_close().
 */
void
admin_release(admin_t host)
{
	if (host == NULL)
		return;

	xlog(D_CALL, "freeing admin_t for %s",
		admin_hostname(host));

	(void)admin_close(host);

	free(host->ad_hostname);
	free(host->ad_nettype);
	free(host);
}

/**
 * Reset error status values
 *
 * @param host admin_t allocated by admin_new()
 */
void
admin_reset(admin_t host)
{
	host->ad_srv_status = FEDFS_ERR_SVRFAULT;
	host->ad_rpc_status = RPC_FAILED;
	host->ad_ldaperr = LDAP_OTHER;
}

/**
 * Materialize a new admin_t object
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param security NUL-terminated C string containing name of security mode
 * @param result OUT: an initialized admin_t
 * @return zero or an errno
 *
 * Caller must free returned object with admin_release()
 */
static int
admin_new(const char *hostname, const char *nettype, const char *security,
		admin_t *result)
{
	rpc_gss_svc_t svc;
	admin_t new;
	int flavor;

	svc = RPCSEC_GSS_SVC_NONE;
	if (strcasecmp(security, "sys") == 0)
		flavor = AUTH_UNIX;
	else if (strcasecmp(security, "unix") == 0)
		flavor = AUTH_UNIX;
	else if (strcasecmp(security, "krb5") == 0) {
		flavor = RPCSEC_GSS;
	} else if (strcasecmp(security, "krb5i") == 0) {
		flavor = RPCSEC_GSS;
		svc = RPCSEC_GSS_SVC_INTEGRITY;
	} else if (strcasecmp(security, "krb5p") == 0) {
		flavor = RPCSEC_GSS;
		svc = RPCSEC_GSS_SVC_PRIVACY;
	} else
		return EINVAL;

	new = calloc(1, sizeof(struct fedfs_admin));
	if (new == NULL)
		return ENOMEM;

	new->ad_hostname = strdup(hostname);
	new->ad_nettype = strdup(nettype);
	new->ad_secflavor = flavor;
	new->ad_gss_svc = svc;
	new->ad_client = NULL;
	new->ad_timeout = admin_rpc_timeout;

	if (new->ad_hostname == NULL || new->ad_nettype == NULL) {
		admin_release(new);
		return ENOMEM;
	}

	xlog(D_CALL, "created admin_t for %s", hostname);

	admin_reset(new);
	*result = new;
	return 0;
}

/**
 * Create an admin_t and open it
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param security NUL-terminated C string containing name of security mode
 * @param result OUT: an initialized admin_t
 * @return zero or an errno
 *
 * Caller must free returned object with admin_release()
 */
int
admin_create(const char *hostname, const char *nettype, const char *security,
		admin_t *result)
{
	admin_t new;
	int err;

	if (hostname == NULL || nettype == NULL ||
	    result == NULL || security == NULL)
		return EINVAL;

	if (strlen(hostname) == 0 || strlen(nettype) == 0 ||
	    strlen(security) == 0)
		return EINVAL;

	err = admin_new(hostname, nettype, security, &new);
	if (err != 0)
		return err;

	err = admin_open(new);
	if (err != 0)
		return err;

	*result = new;
	return 0;
}

/**
 * Server status code returned by the last FedFS operation
 *
 * @param host an initialized admin_t
 * @return a FedFsStatus code
 */
FedFsStatus
admin_status(const admin_t host)
{
	if (host == NULL)
		return FEDFS_ERR_SVRFAULT;
	return host->ad_srv_status;
}

/**
 * LDAP status if server returned FEDFS_ERR_NSDB_LDAP_VAL
 *
 * @param host an initialized admin_t
 * @return an LDAP operation return code
 */
int
admin_ldaperr(const admin_t host)
{
	if (host == NULL)
		return LDAP_OTHER;
	return host->ad_ldaperr;
}

/**
 * Return an RPC create error message string
 *
 * @param prefix NUL-terminated C string containing prefix message
 * @return NUL-terminated C string containing an error message, or NULL
 *
 * Caller must not free the returned buffer.
 */
const char *
admin_open_perror(const char *prefix)
{
	if (prefix == NULL)
		return NULL;
	return clnt_spcreateerror(prefix);
}

/**
 * Return an RPC error message string
 *
 * @param host an initialized admin_t
 * @param prefix NUL-terminated C string containing prefix message
 * @return NUL-terminated C string containing an error message, or NULL
 *
 * Caller must not free the returned buffer.
 */
const char *
admin_perror(admin_t host, const char *prefix)
{
	if (host == NULL || prefix == NULL || host->ad_client == NULL)
		return NULL;
	if (!admin_is_connected(host))
		return NULL;
	return clnt_sperror(host->ad_client, prefix);
}
