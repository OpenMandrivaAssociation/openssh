## Do not apply any unauthorized patches to this package!
## - vdanen 05/18/01
##

# Version of watchdog patch
%define wversion 4.4p1

# Version of the hpn patch
%define hpnver 13v6

# overrides
%define build_skey	 	0
%define build_krb5	 	1
%define build_watchdog   	0
%define build_gnomeaskpass 	1
%define build_ldap       	0
%define build_sftpcontrol    	0
%define build_hpn		0
%define build_audit		0
%define build_libedit		1

%{?_with_skey: %{expand: %%global build_skey 1}}
%{?_without_skey: %{expand: %%global build_skey 0}}
%{?_with_krb5: %{expand: %%global build_krb5 1}}
%{?_without_krb5: %{expand: %%global build_krb5 0}}
%{?_with_watchdog: %{expand: %%global build_watchdog 1}}
%{?_without_watchdog: %{expand: %%global build_watchdog 0}}
%{?_with_gnomeaskpass: %{expand: %%global build_gnomeaskpass 1}}
%{?_without_gnomeaskpass: %{expand: %%global build_gnomeaskpass 0}}
%{?_with_ldap: %{expand: %%global build_ldap 1}}
%{?_without_ldap: %{expand: %%global build_ldap 0}}
%{?_with_sftpcontrol: %{expand: %%global build_sftpcontrol 1}}
%{?_without_sftpcontrol: %{expand: %%global build_sftpcontrol 0}}
%{?_with_hpn: %{expand: %%global build_hpn 1}}
%{?_without_hpn: %{expand: %%global build_hpn 0}}
%{?_with_audit: %{expand: %%global build_audit 1}}
%{?_without_audit: %{expand: %%global build_audit 0}}
%{?_with_libedit: %{expand: %%global build_libedit 1}}
%{?_without_libedit: %{expand: %%global build_libedit 0}}

%define OPENSSH_PATH "/usr/local/bin:/bin:%{_bindir}"
%define XAUTH %{_bindir}/xauth

Summary:	OpenSSH free Secure Shell (SSH) implementation
Name:		openssh
Version:	6.0p1
Release:	5
License:	BSD
Group:		Networking/Remote access
URL:		http://www.openssh.com/
Source0: 	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
Source1: 	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
# ssh-copy-id taken from debian, with "usage" added
Source3:	ssh-copy-id
Source7:	openssh-xinetd
Source9:        README.sftpfilecontrol
# this is never to be applied by default
# http://www.sc.isc.tohoku.ac.jp/~hgot/sources/openssh-watchdog.html
Source10:	openssh-%{wversion}-watchdog.patch.tgz
Source12:	ssh_ldap_key.pl
Source15:	ssh-avahi-integration
Source17:	sshd.pam
Source18:	sshd.init
Source19:	README.3.8p1.upgrade.urpmi
Source20:	README.3.9p1-3.upgrade.urpmi
Source21:	README.hpn
Patch1:		openssh-mdv_conf.diff
# rediffed from openssh-4.4p1-watchdog.patch.tgz
Patch4:		openssh-4.4p1-watchdog.diff
# optional ldap support
# http://dev.inversepath.com/trac/openssh-lpk
#Patch6:		http://dev.inversepath.com/openssh-lpk/openssh-lpk-4.6p1-0.3.9.patch
# new location for the lpk patch.
# rediffed from "svn checkout http://openssh-lpk.googlecode.com/svn/trunk/ openssh-lpk-read-only"
Patch6:		openssh-lpk-5.4p1-0.3.10.diff
# http://sftpfilecontrol.sourceforge.net
# Not applied by default
# P7 is rediffed and slightly adjusted from http://sftplogging.sourceforge.net/download/v1.5/openssh-4.4p1.sftplogging-v1.5.patch
Patch7:		openssh-4.9p1.sftplogging-v1.5.diff
# (tpg) http://www.psc.edu/networking/projects/hpn-ssh/
Patch11:	http://www.psc.edu/networking/projects/hpn-ssh/openssh-5.2p1-hpn%{hpnver}.diff
Patch12:	http://www.psc.edu/networking/projects/hpn-ssh/openssh5.1-peaktput.diff
#gw: from Fedora:
#fix round-robin DNS with GSSAPI authentification
Patch13:	openssh-4.3p2-gssapi-canohost.patch
Patch14:	openssh-4.7p1-audit.patch
Patch17:	openssh-5.1p1-askpass-progress.patch
Patch18:	openssh-4.3p2-askpass-grab-info.patch
Patch19:	openssh-4.0p1-exit-deadlock.patch
Patch21:	openssh_tcp_wrappers.patch
Obsoletes:	ssh
Provides:	ssh
Requires(post): makedev
Requires:	tcp_wrappers
BuildRequires:	groff-for-man
BuildRequires:	openssl-devel
BuildRequires:	pam-devel
BuildRequires:	tcp_wrappers-devel
BuildRequires:	zlib-devel
%if %{build_skey}
BuildRequires:	skey-devel
%endif
%if %{build_krb5}
BuildRequires:	krb5-devel
%endif
%if %{build_gnomeaskpass}
BuildRequires:	gtk+2-devel
%endif
%if %{build_ldap}
BuildRequires: openldap-devel >= 2.0
%endif
%if %{build_audit}
BuildRequires:	audit-devel
%endif
%if %{build_libedit}
BuildRequires:	edit-devel ncurses-devel
%endif
BuildConflicts:	libgssapi-devel
BuildRequires:  systemd-units
BuildRequires:  rpm-helper > 0.24
Requires(pre):  rpm-helper > 0.24
Requires(post): rpm-helper > 0.24
Requires(preun):        rpm-helper > 0.24
Requires(postun):       rpm-helper > 0.24

%description
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package includes the core files necessary for both the OpenSSH
client and server.  To make this package useful, you should also
install openssh-clients, openssh-server, or both.

You can build %{name} with some conditional build swithes;

(ie. use with rpm --rebuild):

--with[out] skey         smartcard support (disabled)
--with[out] krb5         kerberos support (enabled)
--with[out] watchdog     watchdog support (disabled)
--with[out] gnomeaskpass Gnome ask pass support (disabled)
--with[out] ldap         OpenLDAP support (disabled)
--with[out] sftpcontrol  sftp file control support (disabled)
--with[out] hpn          HPN ssh/scp support (disabled)
--with[out] audit        audit support (disabled)
--with[out] libedit      libedit support in sftp (enabled)

%package	clients
Summary:	OpenSSH Secure Shell protocol clients
Group:		Networking/Remote access
Requires:	%{name} = %{version}-%{release}
Obsoletes:	ssh-clients, sftp, ssh
Provides:	ssh-clients, sftp, ssh
# scp was moved from openssh to openssh-clients
# http://qa.mandriva.com/show_bug.cgi?id=17491 
Conflicts:	%{name} <= 4.1p1-6mdk

%description	clients
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package includes the clients necessary to make encrypted connections
to SSH servers.

%package	server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Group:		System/Servers
Requires(pre):	%{name} = %{version}-%{release} 
Requires:	chkconfig >= 0.9 
Requires(pre):	pam >= 0.74
Requires(pre):	rpm-helper
Requires(post):	rpm-helper
Requires(preun): rpm-helper
Requires(postun): rpm-helper
Requires(post): makedev
Requires:	%{name}-clients = %{version}-%{release}
%if %{build_skey}
Requires:	skey
%endif
%if %{build_audit}
BuildRequires:	audit
%endif
Obsoletes:	ssh-server, sshd
Provides:	ssh-server, sshd

%description	server
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package contains the secure shell daemon. The sshd is the server 
part of the secure shell protocol and allows ssh clients to connect to 
your host.

%package askpass-common
Summary: OpenSSH X11 passphrase common scripts
Group: Networking/Remote access

%description askpass-common
OpenSSH X11 passphrase common scripts

%if %{build_gnomeaskpass}
%package	askpass-gnome
Summary:	OpenSSH GNOME passphrase dialog
Group:		Networking/Remote access
Requires:	%{name} = %{version}-%{release}
Requires: 	%{name}-askpass-common
Obsoletes:	ssh-extras
Requires(pre):	update-alternatives
Provides:	%{name}-askpass, ssh-askpass, ssh-extras

%description	askpass-gnome
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package contains the GNOME passphrase dialog.
%endif

%prep
%setup -q -a10

%patch1 -p1 -b .mdkconf
%if %{build_watchdog}
#patch -p0 -s -z .wdog < %{name}-%{wversion}-watchdog.patch
%patch4 -p1 -b .watchdog
%endif
%if %{build_ldap}
sed -i 's|UsePrivilegeSeparation yes|#UsePrivilegeSeparation yes|' sshd_config
%patch6 -p1 -b .lpk
rm -f README.lpk.lpk
%define _default_patch_fuzz 3
%else
%define _default_patch_fuzz 2
%endif
%if %{build_sftpcontrol}
#cat %{SOURCE8} | patch -p1 -s -z .sftpcontrol
echo "This patch is broken or needs to be updated/rediffed"; exit 1
%patch7 -p1 -b .sftplogging-v1.5
# README with license terms for this patch
install -m 0644 %{SOURCE9} .
%endif
%if %{build_hpn}
echo "This patch is broken or needs to be updated/rediffed"; exit 1
%patch11 -p1 -b .hpn
%patch12 -p1 -b .peak
install %{SOURCE21} .
%endif
%patch13 -p1 -b .canohost
%if %{build_audit}
%patch14 -p1 -b .audit
%endif
%patch17 -p1 -b .progress
%patch18 -p1 -b .grab-info
%patch19 -p1 -b .exit-deadlock
%patch21 -p1 -b .tcp_wrappers_mips

install %{SOURCE12} %{SOURCE19} %{SOURCE20} .

install -m 0644 %{SOURCE17} sshd.pam
install -m 0755 %{SOURCE18} sshd.init

# fix attribs
chmod 644 ChangeLog OVERVIEW README* INSTALL CREDITS LICENCE TODO ssh_ldap_key.pl

# http://qa.mandriva.com/show_bug.cgi?id=22957
perl -pi -e "s|_OPENSSH_PATH_|%{OPENSSH_PATH}|g" sshd_config

%build
autoreconf -fi

%serverbuild

%configure2_5x \
    --prefix=%{_prefix} \
    --sysconfdir=%{_sysconfdir}/ssh \
    --mandir=%{_mandir} \
    --libdir=%{_libdir} \
    --libexecdir=%{_libdir}/ssh \
    --datadir=%{_datadir}/ssh \
    --disable-strip \
    --with-tcp-wrappers \
    --with-pam \
    --with-default-path=%{OPENSSH_PATH} \
    --with-xauth=%{XAUTH} \
    --with-privsep-path=/var/empty \
    --without-zlib-version-check \
    --with-maildir=/var/spool/mail \
    --with-sandbox=rlimit \
%if %{build_krb5}
    --with-kerberos5=%{_prefix} \
%endif
%if %{build_skey}
    --with-skey \
%endif
%if %{build_ldap}
    --with-libs="-lldap -llber" \
    --with-cppflags="-DWITH_LDAP_PUBKEY -DLDAP_DEPRECATED" \
%endif
    --with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:%{_sbindir}:%{_bindir} \
%if %{build_libedit}
    --with-libedit \
%else
    --without-libedit \
%endif
%if %{build_audit}
    --with-linux-audit \
%endif

%make

%if %{build_gnomeaskpass}
pushd contrib
    make gnome-ssh-askpass2 CC="%__cc %optflags %ldflags"
    mv gnome-ssh-askpass2 gnome-ssh-askpass
popd
%endif

%install
rm -rf %{buildroot}

%makeinstall_std

install -d %{buildroot}%{_sysconfdir}/ssh
install -d %{buildroot}%{_sysconfdir}/pam.d/
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -d %{buildroot}%{_initrddir}
install -m644 sshd.pam %{buildroot}%{_sysconfdir}/pam.d/sshd
install -m755 sshd.init %{buildroot}%{_initrddir}/sshd

if [[ -f sshd_config.out ]]; then 
	install -m600 sshd_config.out %{buildroot}%{_sysconfdir}/ssh/sshd_config
else 
	install -m600 sshd_config %{buildroot}%{_sysconfdir}/ssh/sshd_config
fi
echo "root" > %{buildroot}%{_sysconfdir}/ssh/denyusers

if [[ -f ssh_config.out ]]; then
    install -m644 ssh_config.out %{buildroot}%{_sysconfdir}/ssh/ssh_config
else
    install -m644 ssh_config %{buildroot}%{_sysconfdir}/ssh/ssh_config
fi
echo "    StrictHostKeyChecking no" >> %{buildroot}%{_sysconfdir}/ssh/ssh_config

mkdir -p %{buildroot}%{_libdir}/ssh

install -d %{buildroot}%{_sysconfdir}/profile.d/
%if %{build_gnomeaskpass}
install -m 755 contrib/gnome-ssh-askpass %{buildroot}%{_libdir}/ssh/gnome-ssh-askpass
%endif

cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-askpass.csh <<EOF
setenv SSH_ASKPASS %{_libdir}/ssh/ssh-askpass
EOF

cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-askpass.sh <<EOF
export SSH_ASKPASS=%{_libdir}/ssh/ssh-askpass
EOF

cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-client.sh <<'EOF'
# fix hanging ssh clients on exit
if [ -n "$BASH_VERSION" ]; then
	shopt -s huponexit
elif [ -n "$ZSH_VERSION" ]; then
	setopt hup
fi
EOF

install -m 0755 %{SOURCE3} %{buildroot}/%{_bindir}/ssh-copy-id
chmod a+x %{buildroot}/%{_bindir}/ssh-copy-id
install -m 644 contrib/ssh-copy-id.1 %{buildroot}/%{_mandir}/man1/

# create pre-authentication directory
mkdir -p %{buildroot}/var/empty

# remove unwanted files
rm -f %{buildroot}%{_libdir}/ssh/ssh-askpass

# xinetd support (tv)
mkdir -p %{buildroot}%{_sysconfdir}/xinetd.d/
install -m 0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/xinetd.d/sshd-xinetd

cat > %{buildroot}%{_sysconfdir}/sysconfig/sshd << EOF
#SSHD="%{_sbindir}/sshd"
#PID_FILE="/var/run/sshd.pid"
#OPTIONS=""
EOF

# avahi integration support (misc)
mkdir -p %{buildroot}%{_sysconfdir}/avahi/services/
install -m 0644 %{SOURCE15} %{buildroot}%{_sysconfdir}/avahi/services/%{name}.service

# make sure strip can touch it
chmod 755 %{buildroot}%{_libdir}/ssh/ssh-keysign

%pre server
%_pre_useradd sshd /var/empty /bin/true

%post server
# do some key management
%{_bindir}/ssh-keygen -A
%_post_service sshd sshd.service

%preun server
%_preun_service sshd sshd.service

%postun server
%_postun_userdel sshd
%_postun_unit sshd.service

%if %{build_gnomeaskpass}
%post askpass-gnome
update-alternatives --install %{_libdir}/ssh/ssh-askpass ssh-askpass %{_libdir}/ssh/gnome-ssh-askpass 20
update-alternatives --install %{_bindir}/ssh-askpass bssh-askpass %{_libdir}/ssh/gnome-ssh-askpass 20

%postun askpass-gnome
[ $1 = 0 ] || exit 0
update-alternatives --remove ssh-askpass %{_libdir}/ssh/gnome-ssh-askpass
update-alternatives --remove bssh-askpass %{_libdir}/ssh/gnome-ssh-askpass
%endif

%files
%doc ChangeLog OVERVIEW README* INSTALL CREDITS LICENCE TODO ssh_ldap_key.pl
%if %{build_ldap}
%doc *.schema
%endif
%if %{build_watchdog}
%doc CHANGES-openssh-watchdog openssh-watchdog.html
%endif
%if %{build_sftpcontrol}
%doc README.sftpfilecontrol
%endif
%{_bindir}/ssh-keygen
%dir %{_sysconfdir}/ssh
%{_bindir}/ssh-keyscan
%attr(4711,root,root) %{_libdir}/ssh/ssh-keysign
%{_libdir}/ssh/ssh-pkcs11-helper
%{_mandir}/man1/ssh-keygen.1*
%{_mandir}/man1/ssh-keyscan.1*
%{_mandir}/man8/ssh-keysign.8*
%{_mandir}/man8/ssh-pkcs11-helper.8*

%files clients
%{_bindir}/scp
%{_bindir}/ssh
%{_bindir}/ssh-agent
%{_bindir}/ssh-add
%{_bindir}/ssh-copy-id
%{_bindir}/slogin
%{_bindir}/sftp
%{_mandir}/man1/scp.1*
%{_mandir}/man1/ssh-copy-id.1*
%{_mandir}/man1/slogin.1*
%{_mandir}/man1/ssh.1*
%{_mandir}/man1/ssh-agent.1*
%{_mandir}/man1/ssh-add.1*
%{_mandir}/man1/sftp.1*
%{_mandir}/man5/ssh_config.5*
%config(noreplace) %{_sysconfdir}/ssh/ssh_config
%{_sysconfdir}/profile.d/90ssh-client.sh

%files server
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/sshd
%{_sbindir}/sshd
%dir %{_libdir}/ssh
%{_libdir}/ssh/sftp-server
%{_mandir}/man5/sshd_config.5*
%{_mandir}/man5/moduli.5*
%{_mandir}/man8/sshd.8*
%{_mandir}/man8/sftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/sshd_config
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/denyusers
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/pam.d/sshd
%config(noreplace) %_sysconfdir/xinetd.d/sshd-xinetd
%config(noreplace) %{_sysconfdir}/avahi/services/%{name}.service
%config(noreplace) %{_sysconfdir}/ssh/moduli
%attr(0755,root,root) %{_initrddir}/sshd
%dir %attr(0755,root,root) /var/empty

%files askpass-common
%{_sysconfdir}/profile.d/90ssh-askpass.*

%if %{build_gnomeaskpass}
%files askpass-gnome
%defattr(-,root,root)
%{_libdir}/ssh/gnome-ssh-askpass
%endif


%changelog
* Thu Jun 28 2012 Dmitry Mikhirev <dmikhirev@mandriva.org> 6.0p1-5
+ Revision: 807343
+ rebuild (emptylog)

* Tue Jun 26 2012 Guilherme Moro <guilherme@mandriva.com> 6.0p1-3
+ Revision: 807059
- Fix systemd scriptlets

* Sat Jun 09 2012 Dmitry Mikhirev <dmikhirev@mandriva.org> 6.0p1-2
+ Revision: 803895
- enable askpass-gnome as it is useful with MATE

* Sun Apr 22 2012 Bernhard Rosenkraenzer <bero@bero.eu> 6.0p1-1
+ Revision: 792720
- Update to 6.0

* Fri Mar 16 2012 Oden Eriksson <oeriksson@mandriva.com> 5.9p1-3
+ Revision: 785272
- rebuilt against new openssl

* Sat Dec 03 2011 Oden Eriksson <oeriksson@mandriva.com> 5.9p1-2
+ Revision: 737413
- gnome-ssh-askpass2.c does not build with gtk+-3.0, disable it for now

  + Matthew Dawkins <mattydaw@mandriva.org>
    - rebuild
    - cleaned up spec
    - removed mkrel, BuildRoot, clean section, defattr
    - removed reqs openssl (both server and clients work w/o it)

* Tue Sep 06 2011 Oden Eriksson <oeriksson@mandriva.com> 5.9p1-1
+ Revision: 698454
- 5.9p1
- spec cleanups
- simplify server key generation
- broke out the x11-ssh-askpass code into its own package (x11-ssh-askpass)

* Sun May 15 2011 Oden Eriksson <oeriksson@mandriva.com> 5.8p2-1
+ Revision: 674747
- 5.8p2
- fix build
- mass rebuild

* Sun Feb 27 2011 Funda Wang <fwang@mandriva.org> 5.8p1-2
+ Revision: 640301
- rebuild to obsolete old packages

* Fri Feb 04 2011 Oden Eriksson <oeriksson@mandriva.com> 5.8p1-1
+ Revision: 635967
- 5.8p1 (fixes CVE-2011-0539)

* Sat Jan 29 2011 Eugeni Dodonov <eugeni@mandriva.com> 5.7p1-1
+ Revision: 633939
- Updated to 5.7p1.
  Rediff P1 and P3.

* Tue Dec 07 2010 Oden Eriksson <oeriksson@mandriva.com> 5.6p1-2mdv2011.0
+ Revision: 613606
- provide a useful debug package

* Tue Aug 24 2010 Funda Wang <fwang@mandriva.org> 5.6p1-1mdv2011.0
+ Revision: 572678
- New version 5.6p1
- use our own build flags

* Mon Jun 07 2010 Eugeni Dodonov <eugeni@mandriva.com> 5.5p1-2mdv2010.1
+ Revision: 547228
- Do not display bogus FAILED messages when stopping service (#58283).

* Fri Apr 16 2010 Eugeni Dodonov <eugeni@mandriva.com> 5.5p1-1mdv2010.1
+ Revision: 535499
- Updated to 5.5p1.

* Mon Apr 05 2010 Funda Wang <fwang@mandriva.org> 5.4p1-3mdv2010.1
+ Revision: 531711
- rebuild for new openssl

* Mon Mar 08 2010 Oden Eriksson <oeriksson@mandriva.com> 5.4p1-2mdv2010.1
+ Revision: 515815
- whoops!, the ldap patch wasn't supposed to be applied per default
- 5.4p1
- dropped upstream added patches
- rediffed two patches
- adjust the spec file for 5.4p1

* Tue Mar 02 2010 Olivier Blin <blino@mandriva.org> 5.3p1-6mdv2010.1
+ Revision: 513571
- kill sshd clients at shutdown (#57782)

* Fri Feb 26 2010 Oden Eriksson <oeriksson@mandriva.com> 5.3p1-5mdv2010.1
+ Revision: 511605
- rebuilt against openssl-0.9.8m

* Fri Jan 15 2010 Oden Eriksson <oeriksson@mandriva.com> 5.3p1-4mdv2010.1
+ Revision: 491719
- fix #55951 (the openssh-server package needs openssl and makedev in Requires(post))

  + JÃ©rÃ´me Quelin <jquelin@mandriva.org>
    - reverting to bash, till all functions get fixed
    - remove bashisms, switch to dash

  + Olivier Blin <blino@mandriva.org>
    - require makedev in post (random/entropy devices are needed by openssl)

* Wed Oct 07 2009 Oden Eriksson <oeriksson@mandriva.com> 5.3p1-2mdv2010.0
+ Revision: 455652
- rediffed most of the third party patches

* Thu Oct 01 2009 Oden Eriksson <oeriksson@mandriva.com> 5.3p1-1mdv2010.0
+ Revision: 452225
- 5.3p1

  + Olivier Blin <blino@mandriva.org>
    - fix build on mips (from Arnaud Patard)

* Thu Sep 03 2009 Christophe Fergeau <cfergeau@mandriva.com> 5.2p1-2mdv2010.0
+ Revision: 426348
- rebuild

* Mon Feb 23 2009 Oden Eriksson <oeriksson@mandriva.com> 5.2p1-1mdv2009.1
+ Revision: 344077
- 5.2p1
- rediffed P1
- dropped one upstream patch (P21)

* Tue Feb 03 2009 Guillaume Rousse <guillomovitch@mandriva.org> 5.1p1-6mdv2009.1
+ Revision: 337115
- keep bash completion in its own package

* Fri Jan 09 2009 Guillaume Rousse <guillomovitch@mandriva.org> 5.1p1-5mdv2009.1
+ Revision: 327518
- bash completion, splitted from main file in upstream project

* Tue Dec 16 2008 Oden Eriksson <oeriksson@mandriva.com> 5.1p1-4mdv2009.1
+ Revision: 314936
- rebuild

* Thu Oct 16 2008 Oden Eriksson <oeriksson@mandriva.com> 5.1p1-3mdv2009.1
+ Revision: 294182
- rebuild

* Mon Sep 29 2008 Oden Eriksson <oeriksson@mandriva.com> 5.1p1-2mdv2009.0
+ Revision: 289727
- rebuild
- fix #43747 (transfering locales with ssh creates problems)

* Tue Aug 05 2008 Oden Eriksson <oeriksson@mandriva.com> 5.1p1-1mdv2009.0
+ Revision: 263950
- hpn13v5
- sync with openssh-5.1p1-2.fc10.src.rpm

* Mon Jul 28 2008 Oden Eriksson <oeriksson@mandriva.com> 5.1p1-0.1mdv2009.0
+ Revision: 251404
- 5.1p1
- rediffed P1,P21
- disabled P22 for now
- 3rd party patches needs to be fixed

* Thu Jul 17 2008 Oden Eriksson <oeriksson@mandriva.com> 5.0p1-5mdv2009.0
+ Revision: 236780
- rebuilt x11-ssh-askpass with LDFLAGS="-Wl,--as-needed"
- rebuild
- added P21, P22 from openssh-5.0p1-1.fc9 - fix race on control
  master and cleanup stale control socket (#436311) patches by
  David Woodhouse
- added P20 from openssh-5.0p1-1.fc9 - set FD_CLOEXEC on client socket
- added P19 from openssh-5.0p1-1.fc9 - don't deadlock on exit with
  multiple X forwarded channels (rh #152432)
- added 3 patches for gnome-ssh-askpass from openssh-5.0p1-1.fc9
- make it possible to build without libedit support (rpmbuild --rebuild --without libedit ...)
- added audit support from openssh-5.0p1-1.fc9 (disabled for now, though it works)
- sync with fc9 (SendEnv AcceptEnv)

* Wed Apr 23 2008 GÃ¶tz Waschk <waschk@mandriva.org> 5.0p1-3mdv2009.0
+ Revision: 196921
- fix gssapi with DNS loadbalanced clusters

* Tue Apr 15 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 5.0p1-2mdv2009.0
+ Revision: 194354
- update HPN SSH/SCP patches against latest openssh version

* Wed Apr 09 2008 Oden Eriksson <oeriksson@mandriva.com> 5.0p1-1mdv2009.0
+ Revision: 192500
- 5.0p1
- drop P2 (CVE-2008-1483 is fixed in 5.0p1)
- 4.9p1
- dropped the chroot patch since another approach is in 4.9p1
- dropped the ctimeout patch since it's in there
- rediffed all patches that are not applied per default, except for the HPN patches

* Thu Mar 27 2008 Gustavo De Nardin <gustavodn@mandriva.com> 4.7p1-9mdv2008.1
+ Revision: 190750
- security fix for CVE-2008-1483

  + Giuseppe GhibÃ² <ghibo@mandriva.com>
    - Move 2007.1 backports ssp flags to a more effective place in the building.

* Mon Mar 17 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 4.7p1-7mdv2008.1
+ Revision: 188362
- new version of HPN patch

* Wed Jan 23 2008 Thierry Vignaud <tv@mandriva.org> 4.7p1-6mdv2008.1
+ Revision: 157259
- rebuild with fixed %%serverbuild macro

* Mon Jan 14 2008 Olivier Blin <blino@mandriva.org> 4.7p1-5mdv2008.1
+ Revision: 151175
- use ConnectTimeout option for banner exchange, to timeout on stuck servers (rediffed from CVS)

* Thu Jan 03 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 4.7p1-4mdv2008.1
+ Revision: 142673
- disable hpn support by default

  + Olivier Blin <blino@mandriva.org>
    - restore BuildRoot

* Tue Jan 01 2008 Tomasz Pawel Gajc <tpg@mandriva.org> 4.7p1-3mdv2008.1
+ Revision: 140105
- add support for High Performance SSH/SCP - HPN-SSH
  o add patch 11, the hpn core
  o add patch 12, which displays peak throughput through the life of the connection
  o add README.hpn, all info about hpn idea

  + Guillaume Rousse <guillomovitch@mandriva.org>
    - no executable bit on profile scriptlets
      order prefix on profile scriptlets
      use herein-documents instead of additional source for profile scriptlets

  + Thierry Vignaud <tv@mandriva.org>
    - kill re-definition of %%buildroot on Pixel's request

* Wed Sep 12 2007 Anssi Hannula <anssi@mandriva.org> 4.7p1-2mdv2008.0
+ Revision: 84669
- show upgrade notes only on relevant upgrades

* Wed Sep 05 2007 Oden Eriksson <oeriksson@mandriva.com> 4.7p1-1mdv2008.0
+ Revision: 80390
- 4.7p1
- rediffed P1,S8
- dropped upstream chan_read_failed patch (P2)
- fixed build deps (edit-devel)

  + Giuseppe GhibÃ² <ghibo@mandriva.com>
    - Add conditional flags for 2007.1 and CD4.

  + Thierry Vignaud <tv@mandriva.org>
    - kill file require on update-alternatives

* Fri Aug 03 2007 Andreas Hasenack <andreas@mandriva.com> 4.6p1-8mdv2008.0
+ Revision: 58559
- updated lpk patch (still not applied by default)

* Mon Jul 02 2007 Andreas Hasenack <andreas@mandriva.com> 4.6p1-7mdv2008.0
+ Revision: 47243
- updated sftplogging patch, which is now called sftpfilecontrol
- added README file for it with the license

* Wed Jun 27 2007 Andreas Hasenack <andreas@mandriva.com> 4.6p1-6mdv2008.0
+ Revision: 45218
- added patch from openssh's bugzilla to fix the chan_read_failed error
  messages in logs (#31664)

* Thu Jun 21 2007 Andreas Hasenack <andreas@mandriva.com> 4.6p1-5mdv2008.0
+ Revision: 42382
- rebuild

* Wed Jun 20 2007 Andreas Hasenack <andreas@mandriva.com> 4.6p1-4mdv2008.0
+ Revision: 41658
- don't use %%{optflags} macro when using %%serverbuild
- don't use -fstack-protector explicitly, as it is now defined by
  the %%serverbuild macro
- move lpk doc to main base package
- remove empty README.lpk.lpk file, caused by patch backup
- install lpk schema files as %%doc if using ldap patch
- updated lpk patch and its url

* Wed Apr 18 2007 Oden Eriksson <oeriksson@mandriva.com> 4.6p1-3mdv2008.0
+ Revision: 14713
- use conditionals for the -fstack-protector gcc clags


* Sat Apr 07 2007 David Walluck <walluck@mandriva.org> 4.6p1-2mdv2007.1
+ Revision: 151271
- enable libedit support for sftp

* Sun Mar 11 2007 Oden Eriksson <oeriksson@mandriva.com> 4.6p1-1mdv2007.1
+ Revision: 141301
- 4.6p1
- new openssh-4.4p1.sftplogging-v1.5.patch (S8)
- rediffed the openssh-lpk-4.3p1-0.3.7.patch patch (P6)
- fixed deps

  + Andreas Hasenack <andreas@mandriva.com>
    - enabled gcc's stack-protector, let's try it

* Sat Jan 20 2007 Olivier Blin <oblin@mandriva.com> 4.5p1-3mdv2007.1
+ Revision: 111120
- use Should-Start/Should-Stop tags for remote_fs system facility in sshd service (#25757)

* Fri Nov 10 2006 Andreas Hasenack <andreas@mandriva.com> 4.5p1-2mdv2007.1
+ Revision: 80618
- rebuild with new openssl
- get rid of svn comment, not needed anymore

* Tue Nov 07 2006 Andreas Hasenack <andreas@mandriva.com> 4.5p1-1mdv2007.0
+ Revision: 77765
- updated to version 4.5p1
- updated to version 4.4p1, fixing CVE-2006-4924,
  CVE-2006-4925 and CVE-2006-5051 (#26249)

  + Oden Eriksson <oeriksson@mandriva.com>
    - don't use bugus config in the lpk patch, it prevents the sshd server from starting...
    - it really links against the shared skey libs, so nuke one build dep
    - kerberos was not found on my cs4 box, using "--with-kerberos5=%%{_prefix}" fixed it (!?)
    - pass "-DLDAP_DEPRECATED" to the CPPFLAGS if building with ldap support

* Thu Aug 03 2006 Andreas Hasenack <andreas@mandriva.com> 4.3p2-12mdv2007.0
+ Revision: 42979
- bunzipped remaining source files
- updated sftploggin patch (still not applied by default)
- fixed pam configuration file for recent pam (#22008)
- removed requirement for xauth (#23086)
- removed workaround for #22736
- added versioned buildrequires for x11-util-cf-files in order
  to fix #22736. Rebuild.
- added other missing buildrequires due to xorg xplit
- re-generate ssh-askpass html doc page again during build

* Mon Jul 31 2006 Helio Chissini de Castro <helio@mandriva.com> 4.3p2-11mdv2007.0
+ Revision: 42821
- Fixed file list
- Wrong.. askpass env should come *before* keyring
- Fixed source list
- Added ordering for askpass script. Same change will be added on keychain
  script

  + Andreas Hasenack <andreas@mandriva.com>
    - add svn warning
    - import openssh-4.3p2-10mdv2007.0

* Fri Jul 28 2006 Helio Chissini de Castro <helio@mandriva.com> 4.3p2-10mdv2007.0
- Created script package askpass-common to enable just one file on profile.d and rely on
correct alternatives, with recent introduction of qt version of ssh-askpass ( separated
package ).
- Nuke the old invalid buildrequires dependency for db1

* Tue Jul 04 2006 Per Øyvind Karlsen <pkarlsen@mandriva.com> 4.3p2-9mdv2007.0
- fix buildrequires
- fix macro-in-%%changelog

* Thu Jun 08 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p2-8mdv2007.0
- fix #22957 (P1 + spec file hack)
- make it backportable for older X
- fix deps

* Mon May 29 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p2-7mdv2007.0
- fix #22736 with a temporary hack

* Mon Mar 06 2006 Buchan Milne <bgmilne@mandriva.org> 4.3p2-5mdk
- update lpk patch to 0.3.7

* Sun Feb 19 2006 Michael Scherer <misc@mandriva.org> 4.3p2-4mdk
- fix avahi config file naming

* Mon Feb 13 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p2-3mdk
- make it backportable for older pam (S16)

* Sun Feb 12 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p2-2mdk
- use "include" directive instead of the deprecated pam_stack.so
  module and provide our own pam configuration file (S16)
- removed patches that touches the initscript, provide our own 
  initscript and remove deprecated calls to "initlog" from there (S17)
- fix attribs on the doc files

* Sun Feb 12 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p2-1mdk
- 4.3p2 (Minor bugfixes)

* Fri Feb 10 2006 Michael Scherer <misc@mandriva.org> 4.3p1-3mdk
- add a avahi service file for ssh and sftp

* Fri Feb 10 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p1-2mdk
- fix deps
- added P12 to make it possible to use a different sshd binary by using
  the /etc/sysconfig/sshd file. also add that file (David Walluck)

* Wed Feb 01 2006 Oden Eriksson <oeriksson@mandriva.com> 4.3p1-1mdk
- 4.3p1 (fixes CVE-2006-0225)
- spec file "massage"
- rediff P1

* Mon Jan 09 2006 Olivier Blin <oblin@mandriva.com> 4.2p1-13mdk
- fix typo in initscript

* Mon Jan 09 2006 Olivier Blin <oblin@mandriva.com> 4.2p1-12mdk
- convert parallel init to LSB

* Mon Jan 02 2006 Oden Eriksson <oeriksson@mandriva.com> 4.2p1-11mdk
- rebuilt due a missing package

* Sun Jan 01 2006 Couriousous <couriousous@mandriva.org> 4.2p1-10mdk
- Add parallel init stuff

* Wed Dec 28 2005 Christiaan Welvaart <cjw@daneel.dyndns.org> 4.2p1-9mdk
- re-add BuildRequires: xorg-x11 (was removed in previous update)

* Mon Dec 05 2005 Andreas Hasenack <andreas@mandriva.com> 4.2p1-8mdk
- fixed X11 buildrequires (used the x11askpass is built)

* Sun Dec 04 2005 Andreas Hasenack <andreas@mandriva.com> 4.2p1-7mdk
- fixed smart card build (but it's still disabled by default)

* Sun Nov 13 2005 Oden Eriksson <oeriksson@mandriva.com> 4.2p1-6mdk
- rebuilt against openssl-0.9.8a

* Thu Nov 10 2005 Olivier Blin <oblin@mandriva.com> 4.2p1-5mdk
- fix gnome-ssh-askpass.sh generation

* Sun Nov 06 2005 Oden Eriksson <oeriksson@mandriva.com> 4.2p1-4mdk
- update S8 (openssh-4.2p1.sftplogging-v1.4.patch)
- update S10 (openssh-4.0p1-watchdog.patch)
- update P10

* Sun Nov 06 2005 Guillaume Rousse <guillomovitch@mandriva.org> 4.2p1-3mdk
- use here-in document for generating profile scripts, so as to get correct installation location

* Thu Oct 13 2005 Oden Eriksson <oeriksson@mandriva.com> 4.2p1-2mdk
- rebuilt against openssl-0.9.7h

* Tue Sep 06 2005 Oden Eriksson <oeriksson@mandriva.com> 4.2p1-1mdk
- 4.2p1 (Minor security fixes)

* Fri Aug 19 2005 Oden Eriksson <oeriksson@mandriva.com> 4.1p1-9mdk
- make the --with[out] stuff work (Andrzej Kukula)

* Wed Aug 17 2005 Leonardo Chiquitto Filho <chiquitto@mandriva.com> 4.1p1-8mdk
- add a conflict on openssh-clients with versions prior to 6mdk because
  of the scp change
- fix typo in description

* Wed Aug 17 2005 Oden Eriksson <oeriksson@mandriva.com> 4.1p1-7mdk
- fix #17491

* Sun Jul 31 2005 Oden Eriksson <oeriksson@mandriva.com> 4.1p1-6mdk
- fix the "executable-marked-as-config-file" errors

* Sun Jul 31 2005 Oden Eriksson <oeriksson@mandriva.com> 4.1p1-5mdk
- updated the ldap public key patch (P6) to v0.3.6

* Wed Jul 06 2005 Stew Benedict <sbenedict@mandriva.com> 4.1p1-4mdk
- openssh-server provides sshd (Zero_Dogg, cooker IRC)
  openssh-client provides ssh

* Wed Jun 15 2005 Stew Benedict <sbenedict@mandriva.com> 4.1p1-3mdk
- --without-zlib-version-check (Oden, for backports)

* Sat Jun 11 2005 Buchan Milne <bgmilne@linux-mandrake.com> 4.1p1-2mdk
- Rebuild

* Wed Jun 01 2005 Stew Benedict <sbenedict@mandriva.com> 4.1p1-1mdk
- 4.1p1
- fix ssh-client.sh (#16180, Claudio)
- construct the x11-ssh-askpass.1.html file manually as it                     
  sometimes seems to fail (Oden)

* Thu May 05 2005 Stew Benedict <sbenedict@mandriva.com> 4.0p1-2mdk
- rebuild, upload bot lost openssh-askpass somewhere

* Tue May 03 2005 Stew Benedict <sbenedict@mandrakesoft.com> 4.0p1-1mdk
- 4.0p1, redo P1, remove P9 (merged upstream)
- new S8 (sftplogging), new P10 (chroot, upstream patch malformed? - fix) 
- new P6, drop P7, reverse a bit of P1 so P6 can apply unchanged (ldap)

* Mon Apr 25 2005 Oden Eriksson <oeriksson@mandriva.com> 3.9p1-10mdk
- rebuilt against latests openssl

* Tue Mar 22 2005 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-9mdk
- README.chroot (Bruno Cornec)

* Mon Mar 21 2005 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-8mdk
- optional chroot build (http://chrootssh.sourceforge.net, Bruno Cornec)
- spec massages - Oden
- use fuzz 3 with sftplogging patch if ldap is used

* Fri Mar 04 2005 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-7mdk
- enable krb5, GSSAPI - (Bugzilla 14222)
- fix "need to reset console after ctrl-c" (Bugzilla 14153, P9)
- script-without-shellbang (Source 4,5,6)

* Mon Jan 03 2005 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-6mdk
- drop reference to renamed README.mdk in description (Dick Gevers)

* Fri Dec 31 2004 Christiaan Welvaart <cjw@daneel.dyndns.org> 3.9p1-5mdk
- add BuildRequires: XFree86 (for rman)

* Mon Dec 27 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-4mdk
- optional sftplogging build (http://sftplogging.sourceforge.net, Josh Sehn)

* Tue Sep 14 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-3mdk
- accept only protocol 2 as default for sshd (redo patch1, #11413)
- rename Source11, add note about protocol change

* Fri Sep 10 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-2mdk
- rediff ldap patch (Buchan Milne)
- add sample ssh_ldap_key.pl (Buchan Milne)

* Fri Aug 20 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.9p1-1mdk
- 3.9p1, rework patch1

* Fri Jul 30 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.8.1p1-3mdk
- move app-defaults file to correct dir (Peggy KUTYLA)

* Thu Jun 17 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.8.1p1-2mdk
- definitive fix for ldap support (patch7, Tibor Pittich)

* Sat Jun 12 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.8.1p1-1mdk
- 3.8.1p1, rework patch1 (config)
- mod to patch6 from Buchan (ldap)
- trigger doesn't need epoch now (was running on rpm -e)

* Fri Jun 11 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.8p1-4mdk
- add README.mdk to docs to explain differences from <= 3.6.1p2
- add trigger to try and catch alternative auth methods on upgrade,
     re-enabling PAM if in use (Bugzilla #9800, thx Buchan)
- add optional (--with ldap) support for authenticating to public keys
     stored in ldap (Buchan Milne)

* Tue Jun 08 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.8p1-3mdk
- add "ForwardX11Trusted yes" to ssh_config so X11 forwarding works 
  (patch1, Bugzilla #9719)

* Tue May 11 2004 Stew Benedict <sbenedict@mandrakesoft.com> 3.8p1-2mdk
- modified pam stack so enabling UsePAM doesn't change
- "PermitRootLogin without-password" behavior (rework patch1)
- "root" in /etc/ssh/denyusers

