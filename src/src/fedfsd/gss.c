/**
 * @file src/fedfsd/gss.c
 * @brief fedfsd support for RPCSEC GSSAPI
 *
 * Todo: Rework when Linux libtirpc gets a standard RPCSEC API
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

#include <sys/socket.h>
#include <sys/resource.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/svc.h>
#include <rpc/svc_auth.h>
#include <gssapi/gssapi.h>

#include "fedfs.h"
#include "nsdb.h"
#include "fedfsd.h"
#include "xlog.h"


/**
 * Internal TI-RPC API for unpacking a GSS credential
 * (Not currently provided by any libtirpc header)
 */
enum auth_stat		_svcauth_gss(struct svc_req *rqst,
					struct rpc_msg *msg,
					bool_t *no_dispatch);

/**
 * TI-RPC API for setting the server's principal name
 * (Not currently provided by any libtirpc header)
 */
bool_t			svcauth_gss_set_svc_name(gss_name_t name);

/**
 * TI-RPC API for retrieving the caller's principal
 * (Not currently provided by any libtirpc header)
 */
char			*svcauth_gss_get_principal(SVCAUTH *auth);


/**
 * Set to TRUE when the GSS authenticator has already sent an RPC reply
 */
bool_t fedfsd_no_dispatch = FALSE;

/**
 * Log a GSS error
 *
 * @param prefix NUL-terminated C string containing log entry prefix
 * @param maj_stat major status to report
 * @param min_stat minor status to report
 */
static void
fedfsd_log_gss_error(const char *prefix, OM_uint32 maj_stat, OM_uint32 min_stat)
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
 * Unmarshal GSS credentials carried by a request
 *
 * @param rqst handle of an incoming request
 * @param msg RPC header information
 * @return status returned from authentication check
 */
static enum auth_stat
fedfsd_authenticate_gss(struct svc_req *rqst, struct rpc_msg *msg)
{
	enum auth_stat stat;

	fedfsd_no_dispatch = FALSE;
	stat = _svcauth_gss(rqst, msg, &fedfsd_no_dispatch);
	xlog(D_GENERAL, "%s: stat = %d, no_dispatch = %d\n",
		__func__, stat, fedfsd_no_dispatch);
	return stat;
}

static _Bool
fedfsd_set_svc_name(void)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc namebuf;
	gss_name_t name;

	namebuf.value = FEDFS_ADMIN_GSS_SERVICE_NAME;
	namebuf.length = strlen(FEDFS_ADMIN_GSS_SERVICE_NAME);

	maj_stat = gss_import_name(&min_stat, &namebuf,
					(gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
					&name);
	if (maj_stat != GSS_S_COMPLETE) {
		fedfsd_log_gss_error("Failed to import service name",
					maj_stat, min_stat);
		return false;
	}

	if (svcauth_gss_set_svc_name(name) != TRUE) {
		(void)gss_release_name(&min_stat, &name);
		return false;
	}
	return true;
}

/**
 * Install call-outs to unmarshal each request's credentials
 *
 * @return true if all handlers were installed successfully.
 *
 * libtirpc already provides handlers for dealing with
 * AUTH_NULL and AUTH_SYS.  These cannot be removed.
 * A handler for RPCSEC_GSS must be installed manually.
 */
_Bool
fedfsd_set_up_authenticators(void)
{
	if (svc_auth_reg(RPCSEC_GSS, fedfsd_authenticate_gss) < 0)
		return false;
	return fedfsd_set_svc_name();
}

/**
 * Extract the RPCSEC GSS principal from an incoming request
 *
 * @param rqstp incoming RPC request
 * @return NUL-terminated C string containing GSS principal
 *
 * Caller must free principal with free(3).
 */
char *
fedfsd_get_gss_cred(struct svc_req *rqstp)
{
	SVCAUTH *auth;

	auth = rqstp->rq_xprt->xp_auth;
	return svcauth_gss_get_principal(auth);
}
