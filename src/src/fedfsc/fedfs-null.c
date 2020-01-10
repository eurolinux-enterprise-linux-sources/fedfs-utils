/**
 * @file src/fedfsc/fedfs-null.c
 * @brief Send a NULL RPC to a FedFS ADMIN server
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>

#include "fedfs.h"
#include "fedfs_admin.h"
#include "admin.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char fedfs_null_opts[] = "?dh:n:s:";

/**
 * Long form command line options
 */
static const struct option fedfs_null_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nettype", 1, NULL, 'n', },
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
fedfs_null_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'netpath')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fprintf(stderr, "\t-s, --security       RPC security level\n");
	fflush(stderr);

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	return EXIT_FAILURE;
}

/**
 * Send a NULL ADMIN request (ping) to a remote fileserver
 *
 * @param host an initialized and opened admin_t
 * @return program exit status
 */
static FedFsStatus
fedfs_null_try(admin_t host)
{
	int status, err;

	status = EXIT_FAILURE;
	err = admin_null(host);
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
		xlog(L_ERROR, "Client failed: %s", strerror(err));
		goto out;
	}

	switch (admin_status(host)) {
	case FEDFS_OK:
		printf("ADMIN service on %s responded to ping\n",
			admin_hostname(host));
		status = EXIT_SUCCESS;
		break;
	default:
		nsdb_print_fedfsstatus(admin_status(host));
	}

out:
	return status;
}

/**
 * Send a NULL ADMIN request (ping) to a remote fileserver
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param security NUL-terminated C string containing RPC security mode
 * @return program exit status
 */
static int
fedfs_null_host(const char *hostname, const char *nettype,
		const char *security)
{
	admin_t host;
	int status;

	status = EXIT_FAILURE;
	switch (admin_create(hostname, nettype, security, &host)) {
	case 0:
		status = fedfs_null_try(host);
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
int main(int argc, char **argv)
{
	char *progname, *hostname, *nettype, *security;
	int arg;

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
	while ((arg = getopt_long(argc, argv, fedfs_null_opts, fedfs_null_longopts, NULL)) != -1) {
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
		default:
			fprintf(stderr, "Invalid command line argument: %c\n", (char)arg);
		case '?':
			return fedfs_null_usage(progname);
		}
	}
	if (optind != argc)
		return fedfs_null_usage(progname);

	return fedfs_null_host(hostname, nettype, security);
}
