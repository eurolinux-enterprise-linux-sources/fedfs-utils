/**
 * @file src/libadmin/gss.c
 * @brief RPCSEC GSS utility functions
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
#include <sys/socket.h>

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <netdb.h>
#include <gssapi/gssapi.h>

#include "fedfs_admin.h"
#include "fedfs.h"
#include "admin-internal.h"
#include "admin.h"
#include "xlog.h"

/**
 * OID for Kerberos v5 GSS mechanism (RFC 2743, section 1.1.4)
 */
static gss_OID_desc	admin_gss_krb5_oid =
				{ 9, "\052\206\110\206\367\022\001\002\002" };

/**
 * List of GSS mechanisms supported by this implementation
 */
static gss_OID_set_desc	admin_gss_mechs = { 1, &admin_gss_krb5_oid };

/**
 * Log a major GSS error
 *
 * @param prefix NUL-terminated C string containing log entry prefix
 * @param maj_stat major status to report
 * @param min_stat minor status to report
 */
static void
admin_log_gss_major_error(const char *prefix, OM_uint32 maj_stat,
		OM_uint32 min_stat)
{
	gss_buffer_desc maj_msg, min_msg;
	OM_uint32 min, msg_ctx;

	msg_ctx = 0;
	gss_display_status(&min, maj_stat, GSS_C_GSS_CODE,
				GSS_C_NULL_OID, &msg_ctx, &maj_msg);
	gss_display_status(&min, min_stat, GSS_C_MECH_CODE,
				GSS_C_NULL_OID, &msg_ctx, &min_msg);

	xlog(D_GENERAL, "%s: %s - %s",
		prefix, (char *)maj_msg.value, (char *)min_msg.value);

	(void)gss_release_buffer(&min, &min_msg);
	(void)gss_release_buffer(&min, &maj_msg);
}

/**
 * Log an unspecified GSS error
 *
 * @param prefix NUL-terminated C string containing log entry prefix
 * @param min_stat minor status to report
 */
static void
admin_log_gss_unspec_error(const char *prefix, OM_uint32 min_stat)
{
	gss_buffer_desc min_msg;
	OM_uint32 min, msg_ctx;

	msg_ctx = 0;
	gss_display_status(&min, min_stat, GSS_C_MECH_CODE,
				GSS_C_NULL_OID, &msg_ctx, &min_msg);

	xlog(D_GENERAL, "%s: %s",
		prefix, (char *)min_msg.value);

	(void)gss_release_buffer(&min, &min_msg);
}

/**
 * Log a GSS error
 *
 * @param prefix NUL-terminated C string containing log entry prefix
 * @param maj_stat major status to report
 * @param min_stat minor status to report
 */
static void
admin_log_gss_error(const char *prefix, OM_uint32 maj_stat, OM_uint32 min_stat)
{
	if (GSS_ROUTINE_ERROR(maj_stat) != GSS_S_FAILURE)
		admin_log_gss_major_error(prefix, maj_stat, min_stat);
	else
		admin_log_gss_unspec_error(prefix, min_stat);
}

/**
 * Return the GSS service name for the ADMIN server
 *
 * @param server NUL-terminated C string containing hostname of server
 * @return a NUL-terminated C string containing the GSS service name
 *
 * Caller must free the returned string with free(3).
 */
static char *
admin_get_gss_svc_name(const char *server)
{
	struct addrinfo hint, *ai;
	char *buffer;
	size_t len;
	int err;

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_family = AF_UNSPEC;
	hint.ai_flags = AI_CANONNAME;

	err = getaddrinfo(server, NULL, &hint, &ai);
	if (err) {
		xlog(D_GENERAL, "%s: %s", __func__, gai_strerror(err));
		return NULL;
	}

	len = strlen(FEDFS_ADMIN_GSS_SERVICE_NAME) + 1 +
		strlen(ai->ai_canonname) + 1;

	buffer = calloc(len, sizeof(char));
	if (buffer == NULL) {
		goto out;
	}

	buffer[0] = '\0';
	strcpy(buffer, FEDFS_ADMIN_GSS_SERVICE_NAME);
	strcat(buffer, "@");
	strcat(buffer, ai->ai_canonname);

	xlog(D_CALL, "Using service name '%s'", buffer);

out:
	freeaddrinfo(ai);
	return buffer;
}

/**
 * Acquire a GSS credential for a user
 *
 * @param name string form of a UID
 * @param cred OUT: fresh credential
 * @return zero or an errno
 *
 * Caller must free the returned credential with gss_release_cred()
 */
static int
admin_acquire_cred(gss_name_t name, gss_cred_id_t *cred)
{
	OM_uint32 maj_stat, min_stat;
	gss_cred_id_t result;

	maj_stat = gss_acquire_cred(&min_stat, name, GSS_C_INDEFINITE,
					&admin_gss_mechs, GSS_C_INITIATE,
					&result, NULL, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		admin_log_gss_error("Failed to acquire credential",
					maj_stat, min_stat);
		return EKEYEXPIRED;
	}

	*cred = result;
	return 0;
}

/**
 * Construct a GSS credential for the current user
 *
 * @param cred OUT: fresh credential
 * @return zero or an errno
 *
 * Caller must free the returned credential with gss_release_cred()
 */
static int
admin_acquire_user_cred(gss_cred_id_t *cred)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc name_buf;
	gss_name_t name;
	int retval, len;
	char buf[16];

	len = snprintf(buf, sizeof(buf), "%u", geteuid());
	name_buf.value = buf;
	name_buf.length = len;

	maj_stat = gss_import_name(&min_stat, &name_buf,
					(gss_OID)GSS_C_NT_STRING_UID_NAME, &name);
	if (maj_stat != GSS_S_COMPLETE) {
		admin_log_gss_error("Failed to import name",
					maj_stat, min_stat);
		return ENOMEM;
	}

	retval = admin_acquire_cred(name, cred);

	(void)gss_release_name(&min_stat, &name);
	return retval;
}

/**
 * Create an AUTH and an associated GSS context
 *
 * @param clnt RPC client
 * @param host an initialized admin_t struct
 * @param auth OUT: a fresh AUTH object
 * @return zero or an errno
 *
 * Caller must destroy returned object with auth_destroy()
 */
int
admin_authgss_create(CLIENT *clnt, admin_t host, AUTH **auth)
{
	struct rpc_gss_sec sec;
	OM_uint32 min_stat;
	char *svc_name;
	int retval;
	AUTH *tmp;

	xlog(D_CALL, "Creating GSS context for server %s",
		admin_hostname(host));

	retval = ENOMEM;
	svc_name = admin_get_gss_svc_name(admin_hostname(host));
	if (svc_name == NULL)
		goto out;

	retval = admin_acquire_user_cred(&sec.cred);
	if (retval != 0)
		goto out;

	sec.mech = &admin_gss_krb5_oid;
	sec.qop = GSS_C_QOP_DEFAULT;
	sec.svc = host->ad_gss_svc;
	sec.req_flags = GSS_C_MUTUAL_FLAG;

	tmp = authgss_create_default(clnt, svc_name, &sec);
	if (tmp == NULL) {
		xlog(D_GENERAL, "cf_stat = %d", rpc_createerr.cf_stat);
		xlog(D_GENERAL, "%s", clnt_spcreateerror(__func__));
		return EACCES;
	}

	*auth = tmp;
	retval = 0;

	(void)gss_release_cred(&min_stat, &sec.cred);

out:
	free(svc_name);
	return retval;
}
