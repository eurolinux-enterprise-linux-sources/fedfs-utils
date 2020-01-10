/**
 * @file src/fedfsd/access.c
 * @brief fedfsd per-request authorization
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
#include <sys/stat.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include <linux/limits.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <libconfig.h>

#include "fedfs.h"
#include "nsdb.h"
#include "fedfsd.h"
#include "xlog.h"

static char fedfsd_access_pathname[PATH_MAX + 1];
static struct stat fedfsd_access_stat;
static config_t fedfsd_acl;

/**
 * Predicate: Is AUTH_NONE access allowed?
 *
 * @return one if AUTH_NONE access is allowed, otherwise zero
 */
static int
fedfsd_none_is_allowed(void)
{
	int value;

	if (config_lookup_bool(&fedfsd_acl, "none", &value) == CONFIG_FALSE)
		return 0;
	if (value == 0)
		return 0;
	return 1;
}

/**
 * Predicate: Is AUTH_UNIX access allowed?
 *
 * @return one if AUTH_UNIX access is allowed, otherwise zero
 */
static int
fedfsd_unix_is_allowed(void)
{
	config_setting_t *setting;

	setting = config_lookup(&fedfsd_acl, "unix.users");
	if (setting != NULL)
		if (config_setting_length(setting) > 0)
			return 1;

	setting = config_lookup(&fedfsd_acl, "unix.groups");
	if (setting != NULL)
		if (config_setting_length(setting) > 0)
			return 1;

	return 0;
}

/**
 * Predicate: Is RPCSEC_GSS Kerberos v5 access allowed?
 *
 * @return one if Kerberos access is allowed, otherwise zero
 *
 * There must be more than zero Kerberos principals, and at
 * least one GSS Kerberos service enabled.
 */
static int
fedfsd_gss_krb5_is_allowed(void)
{
	int count, value, err;
	config_setting_t *setting;

	setting = config_lookup(&fedfsd_acl,
				"gss.kerberos_v5.allowed_principals");
	if (setting == NULL)
		return 0;
	count = config_setting_length(setting);
	if (count == 0)
		return 0;

	count = 0;
	err = config_lookup_bool(&fedfsd_acl,
		"gss.kerberos_v5.required_services.authentication", &value);
	if (err == CONFIG_TRUE)
		count += value;

	err = config_lookup_bool(&fedfsd_acl,
		"gss.kerberos_v5.required_services.integrity", &value);
	if (err == CONFIG_TRUE)
		count += value;

	err = config_lookup_bool(&fedfsd_acl,
		"gss.kerberos_v5.required_services.privacy", &value);
	if (err == CONFIG_TRUE)
		count += value;

	if (count == 0)
		return 0;
	return 1;
}

/**
 * Read and parse the access configuration file
 *
 * @return true if file was parsed, otherwise false
 */
static _Bool
fedfsd_read_config(void)
{
	unsigned count;

	if (stat(fedfsd_access_pathname, &fedfsd_access_stat) == -1) {
		xlog(L_ERROR, "%s: Failed to stat %s: %m",
			__func__, fedfsd_access_pathname);
		return false;
	}

	config_init(&fedfsd_acl);

	if (!config_read_file(&fedfsd_acl, fedfsd_access_pathname)) {
		xlog(L_ERROR, "%s: %s:%d - %s", __func__,
			config_error_file(&fedfsd_acl),
			config_error_line(&fedfsd_acl),
			config_error_text(&fedfsd_acl));
		config_destroy(&fedfsd_acl);
		return false;
	}

	count = fedfsd_none_is_allowed();
	count += fedfsd_unix_is_allowed();
	count += fedfsd_gss_krb5_is_allowed();
	if (count == 0)
		xlog(L_WARNING, "%s allows no access to the ADMIN service",
			fedfsd_access_pathname);
	return true;
}

/**
 * Specify and read the access configuration file
 *
 * @param pathname NUL-terminated C string containing pathname of config file
 * @return true if file was parsed, otherwise false
 */
_Bool
fedfsd_read_access_config(const char *pathname)
{
	if (strlen(pathname) > sizeof(fedfsd_access_pathname)) {
		xlog(L_ERROR, "Pathname of access config file is too long");
		return false;
	}
	strcpy(fedfsd_access_pathname, pathname);

	return fedfsd_read_config();
}

/**
 * Check if access configuration file has been updated
 *
 * @return true if the in-memory config is up to date
 */
static _Bool
fedfsd_reread_access_config(void)
{
	struct stat buf;

	if (stat(fedfsd_access_pathname, &buf) == -1) {
		xlog(L_ERROR, "%s: Failed to stat %s: %m",
			__func__, fedfsd_access_pathname);
		return false;
	}
	if (buf.st_mtime == fedfsd_access_stat.st_mtime) {
		xlog(D_CALL, "%s: cached config still valid",
			__func__);
		return true;
	}
	xlog(D_CALL, "%s: re-reading config file", __func__);

	config_destroy(&fedfsd_acl);
	return fedfsd_read_config();
}

/**
 * Decide if an AUTH_NONE access is authorized
 *
 * @return true if access is authorized
 */
_Bool
fedfsd_auth_none(void)
{
	if (!fedfsd_reread_access_config())
		return false;

	if (fedfsd_none_is_allowed() == 0) {
		xlog(D_CALL, "%s: caller not authorized", __func__);
		return false;
	}
	xlog(D_CALL, "%s: caller authorized", __func__);
	return true;
}

/**
 * Decide if an AUTH_UNIX user matches list element
 *
 * @param users config setting containing a list
 * @param i index of list element to check
 * @param caller UID of requesting user
 * @return true if "caller" matches the list element at "i"
 */
static _Bool
fedfsd_check_unix_name(config_setting_t *users, int i, uid_t caller)
{
	struct passwd *pwd;
	const char *name;

	name = config_setting_get_string_elem(users, i);
	if (name == NULL)
		return false;

	pwd = getpwnam(name);
	if (pwd == NULL)
		return false;

	if (caller != pwd->pw_uid)
		return false;

	xlog(D_CALL, "%s: caller %s authorized",
		__func__, name);
	return true;
}

/**
 * Decide if an AUTH_UNIX user matches list element
 *
 * @param users config setting containing a list
 * @param i index of list element to check
 * @param caller UID of requesting user
 * @return true if "caller" matches the list element at "i"
 */
static _Bool
fedfsd_check_unix_uid(config_setting_t *users, int i, uid_t caller)
{
	config_setting_t *uid;

	uid = config_setting_get_elem(users, i);
	if (uid == NULL)
		return false;

	if (config_setting_type(uid) != CONFIG_TYPE_INT)
		return false;

	if (caller != (uid_t)config_setting_get_int(uid))
		return false;

	xlog(D_CALL, "%s: caller %u authorized",
		__func__, caller);
	return true;
}

/**
 * Decide if an AUTH_UNIX user is authorized
 *
 * @param users config setting containing a list
 * @param caller UID of requesting user
 * @return true if "caller" matches an element in "users"
 */
static _Bool
fedfsd_check_unix_users(config_setting_t *users, uid_t caller)
{
	int i, count;

	count = config_setting_length(users);
	for (i = 0; i < count; i++) {
		if (fedfsd_check_unix_name(users, i, caller))
			return true;
		if (fedfsd_check_unix_uid(users, i, caller))
			return true;
	}

	xlog(D_CALL, "%s: caller %d not authorized",
		__func__, caller);
	return false;
}

/**
 * Decide if an AUTH_UNIX user is authorized
 *
 * @param caller UID of requesting user
 * @return true if access is authorized
 */
static _Bool
fedfsd_auth_unix_user(uid_t caller)
{
	config_setting_t *users;

	users = config_lookup(&fedfsd_acl, "unix.users");
	if (users == NULL) {
		xlog(D_CALL, "%s: caller not authorized", __func__);
		return false;
	}

	return fedfsd_check_unix_users(users, caller);
}

/**
 * Decide if an AUTH_UNIX group matches list element
 *
 * @param groups config setting containing a list
 * @param i index of list element to check
 * @param caller GID of requesting user
 * @return true if "caller" matches the list element at "i"
 */
static _Bool
fedfsd_check_unix_group(config_setting_t *groups, int i, uid_t caller)
{
	struct group *grp;
	const char *name;

	name = config_setting_get_string_elem(groups, i);
	if (name == NULL)
		return false;

	grp = getgrnam(name);
	if (grp == NULL)
		return false;

	if (caller != grp->gr_gid)
		return false;

	xlog(D_CALL, "%s: caller %s authorized",
		__func__, name);
	return true;
}

/**
 * Decide if an AUTH_UNIX user matches list element
 *
 * @param groups config setting containing a list
 * @param i index of list element to check
 * @param caller GID of requesting user
 * @return true if "caller" matches the list element at "i"
 */
static _Bool
fedfsd_check_unix_gid(config_setting_t *groups, int i, gid_t caller)
{
	config_setting_t *gid;

	gid = config_setting_get_elem(groups, i);
	if (gid == NULL)
		return false;

	if (config_setting_type(gid) != CONFIG_TYPE_INT)
		return false;

	if (caller != (gid_t)config_setting_get_int(gid))
		return false;

	xlog(D_CALL, "%s: caller %u authorized",
		__func__, caller);
	return true;
}

/**
 * Decide if an AUTH_UNIX group is authorized
 *
 * @param groups config setting containing a list
 * @param caller GID of requesting user
 * @return true if "caller" matches an element in "users"
 */
static _Bool
fedfsd_check_unix_groups(config_setting_t *groups, gid_t caller)
{
	int i, count;

	count = config_setting_length(groups);
	for (i = 0; i < count; i++) {
		if (fedfsd_check_unix_group(groups, i, caller))
			return true;
		if (fedfsd_check_unix_gid(groups, i, caller))
			return true;
	}
	return false;
}

/**
 * Decide if an AUTH_UNIX group is authorized
 *
 * @param gid primary GID of requesting user
 * @param len count of items in "gids"
 * @param gids array of secondary GIDs of requesting user
 * @return true if access is authorized
 */
static _Bool
fedfsd_auth_unix_group(gid_t gid, unsigned int len, gid_t *gids)
{
	config_setting_t *groups;
	unsigned int i;

	groups = config_lookup(&fedfsd_acl, "unix.groups");
	if (groups == NULL) {
		xlog(D_CALL, "%s: caller not authorized", __func__);
		return false;
	}

	if (fedfsd_check_unix_groups(groups, gid))
		return true;

	for (i = 0; i < len; i++)
		if (fedfsd_check_unix_groups(groups, gids[i]))
			return true;

	xlog(D_CALL, "%s: caller not authorized", __func__);
	return false;
}

/**
 * Decide if an AUTH_UNIX caller is authorized
 *
 * @param rqstp incoming RPC request
 * @return true if caller is authorized to proceed
 */
_Bool
fedfsd_auth_unix(struct svc_req *rqstp)
{
	struct authunix_parms *cred =
			(struct authunix_parms *)rqstp->rq_clntcred;

	xlog(D_CALL, "%s: uid=%d gid=%d",
		__func__, cred->aup_uid, cred->aup_gid);

	if (!fedfsd_reread_access_config())
		return false;

	if (fedfsd_auth_unix_user(cred->aup_uid))
		return true;

	return fedfsd_auth_unix_group(cred->aup_gid,
					cred->aup_len, cred->aup_gids);
}

/**
 * Decide if a caller string matches a list element
 *
 * @param setting config setting containing a list
 * @param i index of list element to check
 * @param caller NUL-terminated C string containing principal to check
 * @return true if "caller" matches the list element at "i"
 */
static _Bool
fedfsd_check_list(config_setting_t *setting, int i, const char *caller)
{
	const char *name;

	name = config_setting_get_string_elem(setting, i);
	if (name == NULL)
		return false;
	return strcasecmp(name, caller) == 0;
}

/*
 * Decide if an RPCSEC_GSS Kerberos v5 principal is authorized
 *
 * @param rqstp incoming RPC request
 * @return true if access is authorized
 */
static _Bool
fedfsd_auth_rpc_gss_krb5_principal(struct svc_req *rqstp)
{
	config_setting_t *principals;
	char *principal;
	_Bool result;
	int i, count;

	principal = fedfsd_get_gss_cred(rqstp);

	result = false;
	principals = config_lookup(&fedfsd_acl,
					"gss.kerberos_v5.allowed_principals");
	if (principals == NULL)
		goto out;

	count = config_setting_length(principals);
	for (i = 0; i < count; i++) {
		if (fedfsd_check_list(principals, i, principal)) {
			result = true;
			break;
		}
	}

out:
	if (!result)
		xlog(D_CALL, "%s: '%s' not authorized", __func__, principal);
	else
		xlog(D_CALL, "%s: '%s' authorized", __func__, principal);

	free(principal);
	return result;
}

/*
 * Decide if an RPCSEC_GSS principal is authorized
 *
 * @param rqstp incoming RPC request
 * @return true if access is authorized
 *
 * This is provisional because the current libtirpc GSS API provides
 * only the caller's princpal, not the GSS mechanism or the GSS
 * service.
 *
 * For now, assume that the GSS mechanism is always "Kerberos v5" and
 * don't check to see if the service is enabled.
 */
_Bool
fedfsd_auth_rpc_gss(struct svc_req *rqstp)
{
	if (!fedfsd_reread_access_config())
		return false;

	if (fedfsd_gss_krb5_is_allowed() == 0) {
		xlog(D_CALL, "%s: GSS callers not authorized", __func__);
		return false;
	}
	return fedfsd_auth_rpc_gss_krb5_principal(rqstp);
}
