/**
 * @file src/fedfsc/fedfs-set-nsdb-params.c
 * @brief Send a FEDFS_SET_NSDB_PARAMS RPC to a FedFS ADMIN server
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

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>

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
static const char fedfs_set_nsdb_params_opts[] = "?df:h:l:n:r:s:";

/**
 * Long form command line options
 */
static const struct option fedfs_set_nsdb_params_longopts[] = {
	{ "certfile", 1, NULL, 'f', },
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nettype", 1, NULL, 'n', },
	{ "nsdbport", 1, NULL, 'r', },
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
fedfs_set_nsdb_params_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname] "
			"[-f certfile] [-l nsdbname] [-r nsdbport]\n\n",
			progname);

	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-f, --certfile       Where to read certificate\n");
	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'netpath')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname to set\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port to set\n");
	fprintf(stderr, "\t-s, --security       RPC security level\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	return EXIT_FAILURE;
}

/**
 * Set NSDB connection parameters on a remote fileserver
 *
 * @param host an initialized and opened admin_t
 * @param nsdb an NSDB hostname and port to set
 * @param cert pointer to certificate data, or NULL
 * @return program exit status
 */
static int
fedfs_set_nsdb_params_try(admin_t host, struct admin_nsdb *nsdb,
		struct admin_cert *cert)
{
	int status, err;

	if (cert == NULL)
		err = admin_set_nsdb_params_none(host, nsdb);
	else
		err = admin_set_nsdb_params_tls(host, nsdb, cert);

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
		printf("Parameters set successfully\n");
		status = EXIT_SUCCESS;
		break;
	default:
		nsdb_print_fedfsstatus(status);
	}

out:
	return status;
}

/**
 * Set NSDB connection parameters on a remote fileserver
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param security NUL-terminated C string containing RPC security mode
 * @param nsdb an NSDB hostname and port
 * @param cert pointer to certificate data, or NULL
 * @return program exit status
 */
static int
fedfs_set_nsdb_params_host(const char *hostname, const char *nettype,
		const char *security, struct admin_nsdb *nsdb,
		struct admin_cert *cert)
{
	admin_t host;
	int status;

	status = EXIT_FAILURE;
	switch (admin_create(hostname, nettype, security, &host)) {
	case 0:
		status = fedfs_set_nsdb_params_try(host, nsdb, cert);
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
			admin_open_perror(hostname));
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
	char *progname, *hostname, *nettype, *security, *certfile;
	struct admin_cert tmp, *cert;
	struct admin_nsdb nsdb;
	FedFsStatus status;
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

	nsdb_env((char **)&nsdb.an_hostname, &nsdb.an_port, NULL, NULL);

	hostname = "localhost";
	nettype = "netpath";
	security = "unix";
	certfile = NULL;
	while ((arg = getopt_long(argc, argv, fedfs_set_nsdb_params_opts, fedfs_set_nsdb_params_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'f':
			certfile = optarg;
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'l':
			if (!nsdb_is_hostname_utf8(optarg)) {
				fprintf(stderr, "NSDB name %s is "
					"not a UTF-8 hostname\n", optarg);
				return fedfs_set_nsdb_params_usage(progname);
			}
			nsdb.an_hostname = optarg;
			break;
		case 'n':
			nettype = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdb.an_port)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				return fedfs_set_nsdb_params_usage(progname);
			}
			break;
		case 's':
			security = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line argument: %c\n", (char)arg);
		case '?':
			return fedfs_set_nsdb_params_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		return fedfs_set_nsdb_params_usage(progname);
	}
	if (nsdb.an_hostname == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		return fedfs_set_nsdb_params_usage(progname);
	}

	nsdb_connsec_crypto_startup();

	status = EXIT_FAILURE;
	if (certfile != NULL) {
		cert = &tmp;
		status = nsdb_connsec_read_pem_file(certfile,
					(char **)&cert->ac_data,
					&cert->ac_len);
		switch (status) {
		case FEDFS_OK:
			break;
		case FEDFS_ERR_INVAL:
			fprintf(stderr, "Invalid certificate material\n");
			goto out;
		default:
			fprintf(stderr, "Failed to validate %s: %s\n",
				certfile, nsdb_display_fedfsstatus(status));
			goto out;
		}
	} else
		cert = NULL;

	status = fedfs_set_nsdb_params_host(hostname, nettype,
						security, &nsdb, cert);
out:
	nsdb_connsec_crypto_shutdown();
	return status;
}
