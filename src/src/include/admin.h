/*
 * @file src/include/admin.h
 * @brief Common public declarations for the ADMIN API
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

#ifndef _FEDFS_ADMIN_API_H_
#define _FEDFS_ADMIN_API_H_

#include <stdbool.h>
#include <netdb.h>

#include "fedfs_admin.h"
#include "fedfs.h"
#include "nsdb.h"

/*
 * Client-side failures are reported as an errno, via the return value
 * of the API functions.
 *
 * Server-side failures are reported as a FedFsStatus code, extracted with
 * the admin_status() function.
 *
 * Client API error codes
 *
 * 0:			RPC successful, check ad_srv_status for server result
 * EACCES:		Security failure
 * EIO:			RPC call or network transport failure
 * EINVAL:		Function was passed invalid parameters, or parameters
 *			that could not be marshalled
 * ENAMETOOLONG:	Problem parsing outgoing or incoming path_array
 * ENOMEM:		Local resource allocation error occurred
 * ENOTCONN:		admin_t object is not connected to remote ADMIN service
 * EOPNOTSUPP:		Client does not support this operation
 */

/**
 ** Arguments and results
 **/

/**
 * NSDB
 */
struct admin_nsdb {
	const char		*an_hostname;
	uint16_t		 an_port;
};

/**
 * FileSet Name
 */
struct admin_fsn {
	const char		*af_uuid;
	struct admin_nsdb	 af_nsdb;
};

/**
 * FileSet Location
 */
struct admin_fsl {
	struct admin_fsl	*al_next;
	const char		*al_uuid;
	const char		*al_hostname;
	uint16_t		 al_port;
	char * const		*al_pathname;
};

/**
 * X.509 certificate material
 */
struct admin_cert {
	unsigned int		 ac_len;
	const char		*ac_data;
};

/**
 * Free an in-memory FSN data structure
 */
void		 admin_free_fsn(struct admin_fsn *fsn);

/**
 * Free a list of in-memory FSL data structures
 */
void		 admin_free_fsls(struct admin_fsl *fsls);

/**
 * Free a certificate buffer
 */
void		 admin_free_cert(struct admin_cert *cert);

/**
 ** API for managing admin_t objects
 **/

/**
 * Object that internally represents an ADMIN service
 */
struct fedfs_admin;
typedef struct fedfs_admin *admin_t;

/**
 * Construct a new admin_t object
 */
int		 admin_create(const char *hostname, const char *nettype,
				const char *security, admin_t *result);

/**
 * Release all resources associated with an admin_t object
 */
void		 admin_release(admin_t host);

/**
 * Get ADMIN service's DNS hostname
 */
const char	*admin_hostname(const admin_t host);

/**
 * Get the length of ADMIN service's DNS hostname
 */
size_t		 admin_hostname_len(const admin_t host);

/**
 * Get the RPC nettype used to connect to ADMIN service
 */
const char	*admin_nettype(const admin_t host);

/**
 * Get the authentication flavor used to connect to ADMIN service
 */
uint32_t	 admin_flavor(const admin_t host);

/**
 * Get the FedFsStatus code returned by the last ADMIN service operation
 */
FedFsStatus	 admin_status(const admin_t host);

/**
 * LDAP status if server returned FEDFS_ERR_NSDB_LDAP_VAL
 */
int		 admin_ldaperr(const admin_t host);

/**
 * Predicate: is "host" connected to a remote ADMIN service?
 */
_Bool		 admin_is_connected(admin_t host);

/**
 * Return an RPC create error message string
 */
const char	*admin_open_perror(const char *prefix);

/**
 * Return an RPC error message string
 */
const char	*admin_perror(admin_t host, const char *prefix);


/**
 ** ADMIN operations defined in the
 ** ADMIN protocol draft, Chapter 5)
 **/

/**
 * FEDFS_NULL (5.1)
 */
int		 admin_null(admin_t host);

/**
 * FEDFS_CREATE_JUNCTION (5.2)
 */
int		 admin_create_junction(admin_t host,
				char * const *path_array,
				struct admin_fsn *fsn);

/**
 * FEDFS_DELETE_JUNCTION (5.3)
 */
int		 admin_delete_junction(admin_t host,
				char * const *path_array);

/**
 * FEDFS_LOOKUP_JUNCTION (5.4) - ResolveType None
 */
int		 admin_lookup_junction_none(admin_t host,
				char * const *path_array,
				struct admin_fsn **fsn);

/**
 * FEDFS_LOOKUP_JUNCTION (5.4) - ResolveType Cached
 */
int		 admin_lookup_junction_cached(admin_t host,
				char * const *path_array,
				struct admin_fsn **fsn,
				struct admin_fsl **fsls);

/**
 * FEDFS_LOOKUP_JUNCTION (5.4) - ResolveType Nsdb
 */
int		 admin_lookup_junction_nsdb(admin_t host,
				char * const *path_array,
				struct admin_fsn **fsn,
				struct admin_fsl **fsls);

/**
 * FEDFS_CREATE_REPLICATION (5.5)
 */
int		 admin_create_replication(admin_t host,
				char * const *path_array,
				struct admin_fsn *fsn);

/**
 * FEDFS_DELETE_REPLICATION (5.6)
 */
int		 admin_delete_replication(admin_t host,
				char * const *path_array);
/**
 * FEDFS_LOOKUP_REPLICATION (5.7) - ResolveType None
 */
int		 admin_lookup_replication_none(admin_t host,
				char * const *path_array,
				struct admin_fsn **fsn);

/**
 * FEDFS_LOOKUP_REPLICATION (5.7) - ResolveType Cached
 */
int		 admin_lookup_replication_cached(admin_t host,
				char * const *path_array,
				struct admin_fsn **fsn,
				struct admin_fsl **fsls);

/**
 * FEDFS_LOOKUP_REPLICATION (5.7) - ResolveType Nsdb
 */
int		 admin_lookup_replication_nsdb(admin_t host,
				char * const *path_array,
				struct admin_fsn **fsn,
				struct admin_fsl **fsls);

/**
 * FEDFS_SET_NSDB_PARAMS (5.8) - ConnectionSec NONE
 */
int		 admin_set_nsdb_params_none(admin_t host,
				const struct admin_nsdb *nsdb);

/**
 * FEDFS_SET_NSDB_PARAMS (5.8) - ConnectionSec TLS
 */
int		 admin_set_nsdb_params_tls(admin_t host,
				const struct admin_nsdb *nsdb,
				const struct admin_cert *cert);

/**
 * FEDFS_GET_NSDB_PARAMS (5.9)
 */
int		 admin_get_nsdb_params(admin_t host,
				struct admin_nsdb *nsdb,
				FedFsConnectionSec *sectype,
				struct admin_cert **cert);

/**
 * FEDFS_GET_LIMITED_NSDB_PARAMS (5.10)
 */
int		 admin_get_limited_nsdb_params(admin_t host,
				struct admin_nsdb *nsdb,
				FedFsConnectionSec *sectype);

#endif	/* !_FEDFS_ADMIN_API_H_ */
