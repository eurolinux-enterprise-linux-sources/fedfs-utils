Name:           fedfs-utils
Version:        0.10.3
Release:        2%{?dist}
Summary:        Utilities for mounting and managing FedFS

Group:          System Environment/Daemons
License:        GPLv2
URL:            http://wiki.linux-nfs.org/wiki/index.php/FedFsUtilsProject
BuildRequires:  libidn-devel libattr-devel libcap-devel openldap-devel
BuildRequires:  sqlite-devel libtirpc-devel libuuid-devel libconfig-devel
BuildRequires:  openssl-devel libxml2-devel uriparser-devel
BuildRequires:  automake libtool glibc-headers
BuildRequires:  python2-devel
BuildRequires:  systemd systemd-units

Source0:        http://oss.oracle.com/projects/%{name}/dist/files/%{name}-%{version}.tar.gz

%global _hardened_build 1
%global unit_name rpcfedfsd
# %define debug_package %{nil}

%description
RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%prep
%setup -q -n %{name}-%{version}

%build
%ifarch s390 s390x
PIE="-fPIE"
%else
PIE="-fpie"
%endif
export PIE
export CFLAGS="$RPM_OPT_FLAGS $ARCH_OPT_FLAGS $PIE"
export LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now"

./autogen.sh
%configure --prefix=/usr
make %{?_smp_mflags}

%install
# make install-strip DESTDIR=%{buildroot}
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}%{_sharedstatedir}/fedfs
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}/nfs4
install -m 644 contrib/init/%{unit_name}.service %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 contrib/init/fedfs %{buildroot}%{_sysconfdir}/sysconfig
mkdir -p %{buildroot}/%{_sysconfdir}/auto.master.d
install -m 644 contrib/init/fedfs.autofs %{buildroot}/%{_sysconfdir}/auto.master.d
mkdir -p %{buildroot}/%{_sysconfdir}/fedfsd
mv %{buildroot}/%{_sysconfdir}/access.conf %{buildroot}/%{_sysconfdir}/fedfsd

# Don't package static libs to encourage use of shared library.
rm -f %{buildroot}%{_libdir}/libnfsjunct.a
rm -f %{buildroot}%{_libdir}/libnfsjunct.la

%package common
Summary:      Common files for FedFS
Group:        System Environment/Daemons
BuildArch:    noarch

%description common
This package contains files common to all of the fedfs packages.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%files common
%doc COPYING README ChangeLog doc/ldap/fedfs.schema doc/ldap/fedfs-schema.ldif
%{_mandir}/man7/fedfs.7.*

%package client
Summary:      Utilities for mounting FedFS domains
Group:        System Environment/Daemons
Requires:     %{name}-common = %{version}-%{release}
Requires:     nfs-utils autofs
Requires(post): systemd-units
Requires(postun): systemd-units
%description client
This package contains the tools needed to mount a FedFS domain and act
as a client.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%files client
/sbin/mount.fedfs
%{_sbindir}/fedfs-map-nfs4
%{_mandir}/man8/mount.fedfs.8.*
%{_mandir}/man8/fedfs-map-nfs4.8.*
%dir /nfs4
%config(noreplace) /%{_sysconfdir}/auto.master.d/fedfs.autofs

%post client
# We may have changed the automounter configuration
/bin/systemctl reload autofs.service >/dev/null 2>&1 || :

%postun client
# We may have changed the automounter configuration
/bin/systemctl reload autofs.service >/dev/null 2>&1 || :

%package nsdbparams
Summary:      The FedFS nsdbparams utility
Group:        System Environment/Daemons
Requires:     %{name}-common = %{version}-%{release}
%description nsdbparams
This package contains the nsdbparams utility, which manages the
NSDB connection parameters used during FedFS junction resolution
and domain administration.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%files nsdbparams
%{_sbindir}/nsdbparams
%{_mandir}/man8/nsdbparams.8.*
%{_mandir}/man7/nsdb-parameters.7.*

%package devel
Summary:      Development files for the FedFS nfs-plugin
Group:        System Environment/Daemons
Requires:     %{name}-lib%{?_isa} = %{version}-%{release}
%description devel
This package contains development files for the FedFS nfs-plugin
library.  This package must be present at nfs-utils build time for
NFS and FedFS junction support to be enabled in nfs-utils.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%files devel
%{_includedir}/nfs-plugin.h

%package lib
Summary:      The FedFS nfs-plugin run-time library
Group:        System Environment/Daemons
Requires:     %{name}-common = %{version}-%{release}
Requires:     %{name}-nsdbparams%{?_isa} = %{version}-%{release}
Requires:     nfs-utils >= 1.2.8
Requires:     kernel >= 3.3.0
%description lib
This package contains the FedFS nfs-plugin run-time library.  This
package must be installed for FedFS junction support to be enabled in
rpc.mountd.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%post lib -p /sbin/ldconfig

%postun lib -p /sbin/ldconfig

%files lib
# We need to include this in the lib package because it is
# dlopen()ed by the junction support code in nfs-utils.
%{_libdir}/libnfsjunct.so
%{_libdir}/libnfsjunct.so.*

%package python
Summary:      FedFS Python utilities
Group:        System Environment/Daemons
BuildArch:    noarch
Requires:     python-ldap openldap-servers

%description python
This package contains Python tools for administering the FedFS
capabilities of a Linux NFS file server.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%files python
%{_bindir}/fedfs-domainroot
%{_bindir}/nsdb-jumpstart
%{python_sitelib}/PyFedfs/*
%{_mandir}/man8/fedfs-domainroot.8.*
%{_mandir}/man8/nsdb-jumpstart.8.*

%package server
Summary:      Utilities for serving FedFS domains
Group:        System Environment/Daemons
Requires:     %{name}-common = %{version}-%{release}
Requires:     %{name}-nsdbparams%{?_isa} = %{version}-%{release}
Requires:     %{name}-lib%{?_isa} = %{version}-%{release}
Requires:     nfs-utils >= 1.2.8
Requires:     kernel >= 3.3.0
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description server
This package contains tools for managing NFS and FedFS junctions
on a Linux NFS file server.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%pre server
getent group fedfs >/dev/null || groupadd -r fedfs
getent passwd fedfs >/dev/null || \
    useradd -r -g fedfs -d %{_sharedstatedir}/fedfs -s /sbin/nologin \
    -c "FedFS Server User" fedfs
exit 0

%post server
%systemd_post %{unit_name}.service

%preun server
%systemd_preun %{unit_name}.service

%postun server
%systemd_postun_with_restart %{unit_name}.service

%files server
%dir %{_sharedstatedir}/fedfs
%dir %{_sysconfdir}/fedfsd
%{_sbindir}/nfsref
%{_sbindir}/rpc.fedfsd
%{_mandir}/man8/nfsref.8.*
%{_mandir}/man8/rpc.fedfsd.8.*
%{_unitdir}/rpcfedfsd.service
%config(noreplace) %{_sysconfdir}/sysconfig/fedfs
%config(noreplace) %{_sysconfdir}/fedfsd/access.conf

%package admin
Summary:      Utilities for administering FedFS domains
Group:        System Environment/Daemons
Requires:     %{name}-common = %{version}-%{release}
Requires:     %{name}-nsdbparams%{?_isa} = %{version}-%{release}
%description admin
This package contains the tools needed to manage a FedFS domain.

RFC 5716 introduces the Federated File System (FedFS, for short). FedFS
is an extensible standardized mechanism by which system administrators
construct a coherent file name space across multiple file servers using
file system referrals.

A file system referral is like a symbolic link to another file system
share, but it is not visible to applications. It behaves like an
auto-mounted directory where a new file system mount is done when an
application first accesses that directory. The arguments of the mount
operation are controlled by information returned by the file server.

Today, file system referral mechanisms exist in several network file
system protocols. FedFS provides its file name space features by
leveraging referral mechanisms already built in to network file system
protocols.  Thus no change to file system protocols or clients is
required.

Currently, the Linux FedFS implementation supports only NFS version 4
referrals. More on NFS version 4 referrals can be found in RFC 3530.
FedFS may support other network file system protocols in the future.

%files admin
%{_sbindir}/fedfs-create-junction
%{_sbindir}/fedfs-create-replication
%{_sbindir}/fedfs-delete-junction
%{_sbindir}/fedfs-delete-replication
%{_sbindir}/fedfs-get-limited-nsdb-params
%{_sbindir}/fedfs-get-nsdb-params
%{_sbindir}/fedfs-lookup-junction
%{_sbindir}/fedfs-lookup-replication
%{_sbindir}/fedfs-null
%{_sbindir}/fedfs-set-nsdb-params
%{_sbindir}/nsdb-*
%{_mandir}/man8/fedfs-create-junction.8.*
%{_mandir}/man8/fedfs-create-replication.8.*
%{_mandir}/man8/fedfs-delete-junction.8.*
%{_mandir}/man8/fedfs-delete-replication.8.*
%{_mandir}/man8/fedfs-get-limited-nsdb-params.8.*
%{_mandir}/man8/fedfs-get-nsdb-params.8.*
%{_mandir}/man8/fedfs-lookup-junction.8.*
%{_mandir}/man8/fedfs-lookup-replication.8.*
%{_mandir}/man8/fedfs-null.8.*
%{_mandir}/man8/fedfs-set-nsdb-params.8.*
%{_mandir}/man8/nsdb-*

%changelog
* Wed Oct 22 2014 Steve Dickson <steved@redhat.com> - 0.10.3-2
- Reworked CFLAGS to put back execshield (bz 983257)

* Tue Oct 21 2014 Steve Dickson <steved@redhat.com> - 0.10.3-1
- Updated to latest upstream release: 0.10.3 (bz 1110228)
- Added the PIE and RELRO CFLAGS (bz 983257)

* Sat Mar  8 2014 Steve Dickson <steved@redhat.com> - 0.10.0-1
- Updated to latest upstream release: 0.10.0 (bz 1069971)

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 0.9.2-4
- Mass rebuild 2014-01-24

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 0.9.2-3
- Mass rebuild 2013-12-27

* Wed Jul 10 2013 Chuck Lever <chuck.lever@oracle.com> - 0.9.2-2
- nfs-utils is required for -client and -server operation
- fedfs-utils-server requires fedfs-utils-lib to resolve junctions
- update package descriptions

* Tue Jun 25 2013 Chuck Lever <chuck.lever@oracle.com> - 0.9.2-1
- update to fedfs-utils-0.9.2
- installing fedfs-utils-client package should configure automounter
- find-debuginfo.sh sometimes fails during "fedpkg local" (bz977556)

* Thu Jun 20 2013 Chuck Lever <chuck.lever@oracle.com> - 0.9.1-1
- update to fedfs-utils-0.9.1.

* Wed Mar 27 2013 Ian Kent <ikent@redhat.com> - 0.9.0-2
- Add missing changelog entry.

* Wed Mar 27 2013 Ian Kent <ikent@redhat.com> - 0.9.0-1
- update to fedfs-utils-0.9.0.

* Tue Feb 12 2013 Ian Kent <ikent@redhat.com> - 0.8.0-11
- change nsdbparams requires to include arch in requires.

* Fri Jan 25 2013 Ian Kent <ikent@redhat.com> - 0.8.0-10
- remove .la libtool archive from devel package (bz889174).
- remove .a static library from devel package ((bz889174).
- make sub-package requires explicit.
- remove duplicate definition of fedfs-set-nsdb-params.8.

* Mon Aug 27 2012 Ian Kent <ikent@redhat.com> - 0.8.0-9
- fix syntax of systemd scriplet macros (bz850396).

* Mon Aug 27 2012 Ian Kent <ikent@redhat.com> - 0.8.0-8
- update systemd scriplet macros (bz850396).

* Thu Aug 2 2012 Ian Kent <ikent@redhat.com> - 0.8.0-7
- some more spec file changes as detailed in the packaging guildlines.

* Thu Aug 2 2012 Ian Kent <ikent@redhat.com> - 0.8.0-6
- add missing systemd scriplets.

* Thu Aug 2 2012 Ian Kent <ikent@redhat.com> - 0.8.0-5
- move libnfsjunct to a lib package to avoid the devel package depending
  on the server package.

* Thu Jul 19 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.8.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Tue Jul 10 2012 Ian Kent <ikent@redhat.com> - 0.8.0-2
- Add fedfs ldap schema to docs of common package.

* Tue Jul 10 2012 Ian Kent <ikent@redhat.com> - 0.8.0-1
- Update to latest upstream version.

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7.3-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Mon Dec 5 2011 Ian Kent <ikent@redhat.com> 0.7.3-2
- add systemd-units to BuildRequires as per systemd doco.

* Wed Nov 30 2011 Jeff Layton <jlayton@redhat.com> 0.7.3-1
- update to 0.7.3 release

* Fri Nov 04 2011 Jeff Layton <jlayton@redhat.com> 0.7.2-1
- update to 0.7.2 release
- add systemd service file for rpc.fedfsd

* Fri Sep 09 2011 Jeff Layton <jlayton@redhat.com> 0.7.0-2
- incorporate review feedback by Volker Fröhlich

* Tue Sep 06 2011 Jeff Layton <jlayton@redhat.com> 0.7.0-1
- Initial package build

