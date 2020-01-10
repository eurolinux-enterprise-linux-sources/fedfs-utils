#               -*- Autoconf -*-
# Initial configure.ac created with autoscan
# Thu Oct 28 16:29:21 EDT 2010
#
# @file configure.ac
# @brief Process this file with autoconf to produce a configure script
#

#
# Copyright 2010, 2011, 2012, 2013 Oracle.  All rights reserved.
#
# This file is part of fedfs-utils.
#
# fedfs-utils is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2.0 as
# published by the Free Software Foundation.
#
# fedfs-utils is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License version 2.0 for more details.
#
# You should have received a copy of the GNU General Public License
# version 2.0 along with fedfs-utils.  If not, see:
#
#	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#

AC_PREREQ([2.65])
AC_INIT([fedfs-utils], [0.10.5], [fedfs-utils-devel@oss.oracle.com])
AC_CANONICAL_BUILD([])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])

# Automake and libtools initialization
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AM_INIT_AUTOMAKE([-Wall -Werror silent-rules])
AM_PATH_PYTHON([2.7])

# configure command line options
AC_ARG_WITH([fedfsuser],
	[AS_HELP_STRING([--with-fedfsuser=name],
		[User name to use when dropping privileges @<:@default=fedfs@:>@])],
	fedfsuser=$withval,
	fedfsuser=fedfs)
	AC_SUBST(fedfsuser)
	AC_DEFINE_UNQUOTED([FEDFS_USER], ["$fedfsuser"],
		[Define to the user name to use when dropping privileges.])
AC_ARG_WITH([statedir],
	[AS_HELP_STRING([--with-statedir=pathname],
		[Default pathname of directory where fedfsd maintains persistent state @<:@default=/var/lib/fedfs@:>@])],
	statedir=$withval,
	statedir=/var/lib/fedfs)
	AC_SUBST(statedir)
	AC_DEFINE_UNQUOTED([FEDFS_DEFAULT_STATEDIR], ["$statedir"],
		[Define to the default pathname of the directory where fedfsd maintains persistent state.])

# Publication date stamp for man pages
pubdate="3 February 2014"
AC_SUBST(pubdate)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_CHECK_PROG([DOT_PRESENT], [dot], [yes], [no])
if test "$DOT_PRESENT" = no; then
	echo "Warning: GraphViz not present on this system. 'make doxy' will fail."
fi

# Needed for doc/rpcl
AC_ARG_VAR([RPCGEN], [rpcgen-like protocol compiler command])
AC_PATH_PROG([RPCGEN], [rpcgen])

# C compiler options
AC_PROG_CC_C99
AC_C_INLINE
AC_C_CONST

# Checks for libraries (essentially, -devel packages)
AC_CHECK_LIB([cap], [cap_set_proc],
		[AC_SUBST([LIBCAP], ["-lcap"])
		 AC_DEFINE([HAVE_LIBCAP], [1],
			   [Define if you have libcap])],
		[AC_MSG_ERROR([libcap not found.])])
AC_CHECK_LIB([idn], [idna_to_ascii_8z],
		[AC_SUBST([LIBIDN], ["-lidn"])
		 AC_DEFINE([HAVE_LIBIDN], [1],
			   [Define if you have libidn])],
		[AC_MSG_ERROR([libidn not found.])])
AC_CHECK_LIB([ldap], [ldap_initialize],
		[AC_SUBST([LIBLDAP], ["-lldap"])
		 AC_DEFINE([HAVE_LIBLDAP], [1],
			   [Define if you have libldap])],
		[AC_MSG_ERROR([libldap not found.])])
AC_CHECK_LIB([lber], [ber_memvfree],
		[AC_SUBST([LIBLBER], ["-llber"])
		 AC_DEFINE([HAVE_LIBLBER], [1],
			   [Define if you have liblber])],
		[AC_MSG_ERROR([liblber not found.])])
AC_CHECK_LIB([sqlite3], [sqlite3_initialize],
		[AC_SUBST([LIBSQLITE3], ["-lsqlite3"])
		 AC_DEFINE([HAVE_LIBSQLITE3], [1],
			   [Define if you have libsqlite3])],
		[AC_MSG_ERROR([libsqlite3 not found.])])
AC_CHECK_LIB([tirpc], [svc_tli_create],
		[AC_SUBST([LIBTIRPC], ["-ltirpc"])
		 AC_DEFINE([HAVE_LIBTIRPC], [1],
			   [Define if you have libtirpc])],
		[AC_MSG_ERROR([libtirpc not found.])])
AC_CHECK_LIB([uuid], [uuid_parse],
		[AC_SUBST([LIBUUID], ["-luuid"])
		 AC_DEFINE([HAVE_LIBUUID], [1],
			   [Define if you have libuuid])],
		[AC_MSG_ERROR([libuuid not found.])])
AC_CHECK_LIB([resolv], [__res_querydomain],
		[AC_SUBST([LIBRESOLV], ["-lresolv"])
		 AC_DEFINE([HAVE_LIBRESOLV], [1],
			   [Define if you have libresolv])],
		[AC_MSG_ERROR([libresolv not found.])])
AC_CHECK_LIB([xml2], [xmlParseFile],
		[AC_SUBST([LIBXML2], ["-lxml2"])
		 AC_DEFINE([HAVE_LIBXML2], [1],
			   [Define if you have libxml2])],
		[AC_MSG_ERROR([libxml2 not found.])])
AC_CHECK_LIB([uriparser], [uriParseUriA],
		[AC_SUBST([LIBURIPARSER], ["-luriparser"])
		 AC_DEFINE([HAVE_LIBURIPARSER], [1],
			   [Define if you have liburiparser])],
		[AC_MSG_ERROR([liburiparser not found.])])
AC_CHECK_LIB([crypto], [X509_LOOKUP_file],
		[AC_SUBST([LIBCRYPTO], ["-lcrypto"])
		 AC_DEFINE([HAVE_LIBCRYPTO], [1],
			   [Define if you have libcrypto])],
		[AC_MSG_ERROR([libcrypto not found.])])
AC_CHECK_LIB([ssl], [SSL_CTX_new],
		[AC_SUBST([LIBSSL], ["-lssl"])
		 AC_DEFINE([HAVE_LIBSSL], [1],
			   [Define if you have libssl])],
		[AC_MSG_ERROR([libssl not found.])])
AC_CHECK_LIB([gssapi_krb5], [gss_acquire_cred],
		[AC_SUBST([LIBGSSAPI_KRB5], ["-lgssapi_krb5"])
		 AC_DEFINE([HAVE_LIBGSSAPI_KRB5], [1],
			   [Define if you have libgssapi_krb5])],
		[AC_MSG_ERROR([libgssapi_krb5 not found.])])
AC_CHECK_LIB([config], [config_lookup],
		[AC_SUBST([LIBCONFIG], ["-lconfig"])
		 AC_DEFINE([HAVE_LIBCONFIG], [1],
			   [Define if you have libconfig])],
		[AC_MSG_ERROR([libconfig not found.])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h langinfo.h locale.h memory.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h syslog.h termios.h unistd.h wchar.h])
AC_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit memset nl_langinfo pathconf setlocale socket strcasecmp strchr strdup strerror strndup strrchr strtoul])

# Check whether exec_prefix=/usr:
root_sbindir="${sbindir}"
case $exec_prefix:$prefix in
NONE:NONE | NONE:/usr | /usr:*)
	root_sbindir="/sbin"
esac

AC_SUBST([root_sbindir])

AC_CONFIG_FILES([Makefile
                 contrib/Makefile
                 contrib/init/Makefile
                 contrib/ldap/Makefile
                 doc/Makefile
                 doc/ldap/Makefile
                 doc/man/Makefile
                 doc/man/fedfs.7
                 doc/man/nsdb-parameters.7
                 doc/man/fedfs-create-junction.8
                 doc/man/fedfs-create-replication.8
                 doc/man/fedfs-delete-junction.8
                 doc/man/fedfs-delete-replication.8
                 doc/man/fedfs-domainroot.8
                 doc/man/fedfs-get-limited-nsdb-params.8
                 doc/man/fedfs-get-nsdb-params.8
                 doc/man/fedfs-lookup-junction.8
                 doc/man/fedfs-lookup-replication.8
                 doc/man/fedfs-map-nfs4.8
                 doc/man/fedfs-null.8
                 doc/man/fedfs-set-nsdb-params.8
                 doc/man/mount.fedfs.8
                 doc/man/nfsref.8
                 doc/man/nsdb-annotate.8
                 doc/man/nsdb-create-fsl.8
                 doc/man/nsdb-create-fsn.8
                 doc/man/nsdb-delete-fsl.8
                 doc/man/nsdb-delete-fsn.8
                 doc/man/nsdb-delete-nsdb.8
                 doc/man/nsdb-describe.8
                 doc/man/nsdb-jumpstart.8
                 doc/man/nsdb-list.8
                 doc/man/nsdb-nces.8
                 doc/man/nsdbparams.8
                 doc/man/nsdb-remove-nci.8
                 doc/man/nsdb-resolve-fsn.8
                 doc/man/nsdb-simple-nce.8
                 doc/man/nsdb-update-fsl.8
                 doc/man/nsdb-update-nci.8
                 doc/man/rpc.fedfsd.8
                 doc/rpcl/Makefile
                 src/Makefile
                 src/domainroot/fedfs-domainroot
                 src/domainroot/Makefile
                 src/fedfsc/Makefile
                 src/fedfsd/Makefile
                 src/include/Makefile
                 src/jumpstart/nsdb-jumpstart
                 src/jumpstart/Makefile
                 src/libadmin/Makefile
                 src/libjunction/Makefile
                 src/libnsdb/Makefile
                 src/libparser/Makefile
                 src/libsi/Makefile
                 src/libxlog/Makefile
                 src/mount/Makefile
                 src/nfsref/Makefile
                 src/nsdbc/Makefile
                 src/nsdbparams/Makefile
                 src/PyFedfs/Makefile
                 src/PyFedfs/domainroot/Makefile
                 src/PyFedfs/jumpstart/Makefile
                 src/plug-ins/Makefile
                 sysconf/Makefile])
AC_OUTPUT
