/**
 * @file src/fedfsc/fedfs-lookup-junction.c
 * @brief Send a FEDFS_LOOKUP_JUNCTION RPC to a FedFS ADMIN server
 */

/*
 * Copyright 2010, 2013 Oracle.  All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>

#include <ldap.h>

#include "fedfs.h"
#include "fedfs_admin.h"
#include "admin.h"
#include "nsdb.h"
#include "junction.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char fedfs_lookup_junction_opts[] = "?dh:n:t:s:";

/**
 * Long form command line options
 */
static const struct option fedfs_lookup_junction_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nettype", 1, NULL, 'n', },
	{ "resolvetype", 1, NULL, 't', },
	{ "security", 1, NULL, 's', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 * @return program exit status
 */
static int
fedfs_lookup_junction_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname] "
			"[-t <none|cache|nsdb>] path\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'netpath')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fprintf(stderr, "\t-t, --resolvetype    Type of desired result (default: 'none')\n");
	fprintf(stderr, "\t-s, --security       RPC security level\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	return EXIT_FAILURE;
}

/**
 * Display one FSL in a FEDFS_LOOKUP_JUNCTION result
 *
 * @param fsl FSL record to display
 */
static void
fedfs_lookup_junction_print_fsl(struct admin_fsl *fsl)
{
	unsigned int i;

	printf(" FSL UUID: %s\n", fsl->al_uuid);

	printf(" FSL hostname: %s:%u\n",
		fsl->al_hostname, fsl->al_port);

	if (fsl->al_pathname[0] == NULL)
		printf(" FSL NFS pathname: /\n");
	else {
		printf(" FSL NFS pathname: ");
		for (i = 0; fsl->al_pathname[i] != NULL; i++)
			printf("/%s", fsl->al_pathname[i]);
		printf("\n");
	}
}

/**
 * Display FSLs returned by a FEDFS_LOOKUP_JUNCTION request
 *
 * @param fsl list of FSLs returned from the server
 */
static void
fedfs_lookup_junction_print_fsls(struct admin_fsl *fsl)
{
	if (fsl == NULL)
		return;

	printf("Returned FSLs:\n");
	while (fsl != NULL) {
		fedfs_lookup_junction_print_fsl(fsl);
		fsl = fsl->al_next;
	}
}

/**
 * Look up a junction on a remote fileserver
 *
 * @param host an initialized and opened admin_t
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param request requested resolution type
 * @return program exit status
 */
static FedFsStatus
fedfs_lookup_junction_try(admin_t host, char * const *path_array, int request)
{
	struct admin_fsl *fsls;
	struct admin_fsn *fsn;
	int status, err;

	switch (request) {
	case 0:
		fsls = NULL;
		err = admin_lookup_junction_none(host, path_array, &fsn);
		break;
	case 1:
		err = admin_lookup_junction_cached(host, path_array,
								&fsn, &fsls);
		break;
	case 2:
		err = admin_lookup_junction_nsdb(host, path_array,
								&fsn, &fsls);
		break;
	}

	status = EXIT_FAILURE;
	switch (err) {
	case 0:
		break;
	case EACCES:
		xlog(L_ERROR, "%s: access denied", admin_hostname(host));
		xlog(D_GENERAL, "%s",
			admin_perror(host, admin_hostname(host)));
		goto out;
	case EIO:
		xlog(L_ERROR, "%s",
			admin_perror(host, admin_hostname(host)));
		goto out;
	default:
		xlog(L_ERROR, "ADMIN client: %s", strerror(err));
		goto out;
	}

	switch (admin_status(host)) {
	case FEDFS_OK:
		printf("FSN UUID: %s\n", fsn->af_uuid);
		printf("NSDB: %s:%u\n",
			fsn->af_nsdb.an_hostname,
			fsn->af_nsdb.an_port);
		admin_free_fsn(fsn);
		if (request > 0) {
			fedfs_lookup_junction_print_fsls(fsls);
			admin_free_fsls(fsls);
		}
		status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "LDAP result code (%d): %s\n",
			admin_ldaperr(host),
			ldap_err2string(admin_ldaperr(host)));
	case FEDFS_ERR_NSDB_PARAMS:
		printf("No connection parameters found\n");
		break;
	default:
		nsdb_print_fedfsstatus(admin_status(host));
	}

out:
	return status;
}

/**
 * Look up a junction on a remote fileserver
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param security NUL-terminated C string containing RPC security mode
 * @param path_array an array of NUL-terminated C strings containing pathname components
 * @param request requested resolution type
 * @return program exit status
 */
static int
fedfs_lookup_junction_host(const char *hostname, const char *nettype,
		const char *security, char * const *path_array, int request)
{
	admin_t host;
	int status;

	status = EXIT_FAILURE;
	switch (admin_create(hostname, nettype, security, &host)) {
	case 0:
		status = fedfs_lookup_junction_try(host, path_array, request);
		admin_release(host);
		break;
	case EINVAL:
		xlog(L_ERROR, "Invalid command line parameter");
		break;
	case EACCES:
		xlog(L_ERROR, "Failed to authenticate server");
		break;
	case EKEYEXPIRED:
		xlog(L_ERROR, "User credentials not found");
		break;
	default:
		xlog(L_ERROR, "%s",
			admin_open_perror(admin_hostname(host)));
	}

	return status;
}

/**
 * Program entry point
 *
 * @param argc count of command line arguments
 * @param argv array of NUL-terminated C strings containing command line arguments
 * @return program exit status
 */
int
main(int argc, char **argv)
{
	char *progname, *hostname, *nettype, *path, *security, *resolvetype;
	int arg, status, request;
	FedFsStatus retval;
	char **path_array;

	(void)setlocale(LC_ALL, "");
	(void)umask(S_IRWXO);

	/* Set the basename */
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	/* For the libraries */
	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open(progname);

	hostname = "localhost";
	nettype = "netpath";
	security = "unix";
	resolvetype = "none";
	while ((arg = getopt_long(argc, argv, fedfs_lookup_junction_opts,
				fedfs_lookup_junction_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'n':
			nettype = optarg;
			break;
		case 's':
			security = optarg;
			break;
		case 't':
			resolvetype = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line argument: %c\n", (char)arg);
		case '?':
			return fedfs_lookup_junction_usage(progname);
		}
	}
	if (argc == optind + 1)
		path = argv[optind];
	else if (argc > optind + 1) {
		fprintf(stderr, "Unrecognized positional parameters\n");
		return fedfs_lookup_junction_usage(progname);
	} else {
		fprintf(stderr, "No junction pathname was specified\n");
		return fedfs_lookup_junction_usage(progname);
	}

	if (strcmp(resolvetype, "0") == 0 ||
	    strcasecmp(resolvetype, "none") == 0 ||
	    strcasecmp(resolvetype, "fedfs_resolve_none") == 0)
		request = 0;
	else if (strcmp(resolvetype, "1") == 0 ||
	    strcasecmp(resolvetype, "cache") == 0 ||
	    strcasecmp(resolvetype, "fedfs_resolve_cache") == 0)
		request = 1;
	else if (strcmp(resolvetype, "2") == 0 ||
	    strcasecmp(resolvetype, "nsdb") == 0 ||
	    strcasecmp(resolvetype, "fedfs_resolve_nsdb") == 0)
		request = 2;
	else {
		fprintf(stderr, "Unrecognized resolvetype\n");
		return EXIT_FAILURE;
	}

	retval = nsdb_posix_to_path_array(path, &path_array);
	if (retval != FEDFS_OK) {
		fprintf(stderr, "Failed to encode pathname: %s",
			nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	status = fedfs_lookup_junction_host(hostname, nettype,
						security, path_array, request);

	nsdb_free_string_array(path_array);
	return status;
}
