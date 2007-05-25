## Do not apply any unauthorized patches to this package!
## - vdanen 05/18/01
##

# Version of ssh-askpass
%define aversion 1.2.4.1
# Version of watchdog patch
%define wversion 4.4p1

# overrides
%define build_skey	 	0
%define build_krb5	 	1
%define build_scard	 	0
%define build_watchdog   	0
%define build_x11askpass	1
%define build_gnomeaskpass 	1
%define build_ldap       	0
%define build_sftplog    	0
%define build_chroot	 	0
%{?_with_skey: %{expand: %%global build_skey 1}}
%{?_without_skey: %{expand: %%global build_skey 0}}
%{?_with_krb5: %{expand: %%global build_krb5 1}}
%{?_without_krb5: %{expand: %%global build_krb5 0}}
%{?_with_watchdog: %{expand: %%global build_watchdog 1}}
%{?_without_watchdog: %{expand: %%global build_watchdog 0}}
%{?_with_smartcard: %{expand: %%global build_scard 1}}
%{?_without_smartcard: %{expand: %%global build_scard 0}}
%{?_with_x11askpass: %{expand: %%global build_x11askpass 1}}
%{?_without_x11askpass: %{expand: %%global build_x11askpass 0}}
%{?_with_gnomeaskpass: %{expand: %%global build_gnomeaskpass 1}}
%{?_without_gnomeaskpass: %{expand: %%global build_gnomeaskpass 0}}
%{?_with_ldap: %{expand: %%global build_ldap 1}}
%{?_without_ldap: %{expand: %%global build_ldap 0}}
%{?_with_sftplog: %{expand: %%global build_sftplog 1}}
%{?_without_sftplog: %{expand: %%global build_sftplog 0}}
%{?_with_chroot: %{expand: %%global build_chroot 1}}
%{?_without_chroot: %{expand: %%global build_chroot 0}}

%if %{mdkversion} < 200700
%define OPENSSH_PATH "/usr/local/bin:/bin:%{_bindir}:/usr/X11R6/bin"
%define XAUTH /usr/X11R6/bin/xauth
%else
%define OPENSSH_PATH "/usr/local/bin:/bin:%{_bindir}"
%define XAUTH %{_bindir}/xauth
%endif

Summary:	OpenSSH free Secure Shell (SSH) implementation
Name:		openssh
Version:	4.6p1
Release:	%mkrel 3
License:	BSD
Group:		Networking/Remote access
URL:		http://www.openssh.com/
Source0: 	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
Source1: 	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
Source2:	http://www.ntrnet.net/~jmknoble/software/x11-ssh-askpass/x11-ssh-askpass-%{aversion}.tar.bz2
# ssh-copy-id taken from debian, with "usage" added
Source3:	ssh-copy-id
Source6:	ssh-client.sh
Source7:	openssh-xinetd
# (sb) sftp logging patch http://sftplogging.sourceforge.net/
# Not applied by default
Source8: http://sftplogging.sourceforge.net/download/v1.5/openssh-4.4p1.sftplogging-v1.5.patch
# this is never to be applied by default 
# http://www.sc.isc.tohoku.ac.jp/~hgot/sources/openssh-watchdog.html
Source10:	openssh-%{wversion}-watchdog.patch.tgz
Source11:	README.update.urpmi
Source12:	ssh_ldap_key.pl
Source13:	sftplogging-installation.html
Source14:	README.chroot
Source15:	ssh-avahi-integration
Source16:	sshd.pam-0.77
Source17:	sshd.pam
Source18:	sshd.init
Patch1:		openssh-4.3p2-mdv_conf.diff
# authorized by Damien Miller <djm@openbsd.com>
Patch3:		openssh-3.1p1-check-only-ssl-version.patch
# (sb) http://www.opendarwin.org/projects/openssh-lpk/files/
# optional ldap support
# http://dev.inversepath.com/trac/openssh-lpk
Patch6:		http://dev.inversepath.com/openssh-lpk/openssh-lpk-4.5p1-0.3.8.patch
# (sb) http://chrootssh.sourceforge.net
# http://chrootssh.sourceforge.net/download/openssh-4.2p1-chroot.tar.gz
Patch10:	openssh-4.2p1-osshChroot.diff
Obsoletes:	ssh
Provides:	ssh
Requires(post): openssl >= 0.9.7
Requires(preun): openssl >= 0.9.7
Requires:	tcp_wrappers
BuildRequires:	groff-for-man
BuildRequires:  libedit-devel
BuildRequires:	openssl-devel >= 0.9.7
BuildRequires:	pam-devel
BuildRequires:	tcp_wrappers-devel
BuildRequires:	zlib-devel
%if %{build_skey}
BuildRequires:	skey-devel
%endif
%if %{build_scard}
BuildRequires:	opensc-devel
%endif
%if %{build_krb5}
BuildRequires:	krb5-devel
%endif
%if %{build_x11askpass}
%if %{mdkversion} < 200700
BuildRequires:  X11-devel xorg-x11
%else
BuildRequires:	imake
BuildRequires:	rman
# http://qa.mandriva.com/show_bug.cgi?id=22736
BuildRequires:	x11-util-cf-files >= 1.0.2
BuildRequires:	gccmakedep
BuildRequires:	libx11-devel
BuildRequires:	libxt-devel
%endif
%endif
%if %{build_gnomeaskpass}
BuildRequires:	gtk+2-devel
%endif
%if %{build_ldap}
BuildRequires: openldap-devel >= 2.0
%endif
BuildConflicts:	libgssapi-devel
BuildRoot:	%{_tmppath}/%{name}-%{version}-buildroot

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
--with[out] x11askpass   X11 ask pass support (enabled)
--with[out] gnomeaskpass Gnome ask pass support (enabled)
--with[out] ldap         OpenLDAP support (disabled)
--with[out] sftplog      sftp logging support (disabled)
--with[out] chroot       chroot support (disabled)

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
Requires(pre):	%{name} = %{version}-%{release} chkconfig >= 0.9 
Requires(pre):	pam >= 0.74
Requires(pre):	rpm-helper
Requires(post):	rpm-helper
Requires(preun): rpm-helper
Requires(postun): rpm-helper
Requires:	%{name}-clients = %{version}-%{release}
%if %{build_skey}
Requires:	skey
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

%if %{build_x11askpass}
%package	askpass
Summary:	OpenSSH X11 passphrase dialog
Group:		Networking/Remote access
Requires:	%{name} = %{version}-%{release}
Requires: 	%{name}-askpass-common
Obsoletes:	ssh-extras, ssh-askpass
Provides:	ssh-extras, ssh-askpass
Requires(pre):	/usr/sbin/update-alternatives

%description	askpass
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.  X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's rework of the last free version of SSH, bringing it
up to date in terms of security and features, as well as removing all 
patented algorithms to separate libraries (OpenSSL).

This package contains Jim Knoble's <jmknoble@pobox.com> X11 passphrase 
dialog.
%endif

%if %{build_gnomeaskpass}
%package	askpass-gnome
Summary:	OpenSSH GNOME passphrase dialog
Group:		Networking/Remote access
Requires:	%{name} = %{version}-%{release}
Requires: 	%{name}-askpass-common
Obsoletes:	ssh-extras
Requires(pre):	/usr/sbin/update-alternatives
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
%if %{build_x11askpass}
echo "Building with x11 askpass..."
%endif
%if %{build_gnomeaskpass}
echo "Building with GNOME askpass..."
%endif
%if %{build_krb5}
echo "Building with Kerberos5 support..."
%endif
%if %{build_skey}
echo "Building with S/KEY support..."
%endif
%if %{build_scard}
echo "Building with smartcard support..."
%endif
%if %{build_watchdog}
echo "Building with watchdog support..."
%endif
%if %{build_ldap}
echo "Buiding with support for authenticating to public keys in ldap"
%endif
%if %{build_sftplog}
echo "Buiding with support for sftp logging"
%endif
%if %{build_chroot}
echo "Buiding with support for ssh chroot"
%endif

%setup -q -a2 -a10

%patch1 -p1 -b .mdkconf
%patch3 -p1 -b .ssl_ver
%if %{build_watchdog}
patch -p0 -s -z .wdog < %{name}-%{wversion}-watchdog.patch
%endif
%if %{build_ldap}
sed -i 's|UsePrivilegeSeparation yes|#UsePrivilegeSeparation yes|' sshd_config
%patch6 -p1 -b .lpk
%define fuzz 3
%else
%define fuzz 2
%endif
%if %{build_sftplog}
#cat %{SOURCE8} | patch -p1 -F %{fuzz} -s -z .sftplog
# XXX - fuzz?!
cat %{SOURCE8} | patch -p1 -s -z .sftplog
install -m 0644 %{SOURCE13} .
%endif
%if %{build_chroot}
%patch10 -p1 -b .chroot
%endif
install %{SOURCE11} %{SOURCE12} %{SOURCE14} .

# fix conditional pam config file
%if %{mdkversion} < 200610
install -m 0644 %{SOURCE16} sshd.pam
%else
install -m 0644 %{SOURCE17} sshd.pam
%endif

install -m 0755 %{SOURCE18} sshd.init

# fix attribs
chmod 644 ChangeLog OVERVIEW README* INSTALL CREDITS LICENCE TODO ssh_ldap_key.pl

# http://qa.mandriva.com/show_bug.cgi?id=22957
perl -pi -e "s|_OPENSSH_PATH_|%{OPENSSH_PATH}|g" sshd_config

%build

%serverbuild

%if %{build_x11askpass}
pushd x11-ssh-askpass-%{aversion}

CFLAGS="%{optflags}" ./configure \
    --prefix=%{_prefix} --libdir=%{_libdir} \
    --mandir=%{_mandir} --libexecdir=%{_libdir}/ssh \
    --with-app-defaults-dir=%{_sysconfdir}/X11/app-defaults \
    --with-libedit
xmkmf -a

%ifarch x86_64
perl -pi -e "s|/usr/lib\b|%{_libdir}|g" Makefile
perl -pi -e "s|i586-mandriva-linux-gnu|x86_64-mandriva-linux-gnu|g" Makefile
perl -pi -e "s|%{_libdir}/gcc/|/usr/lib/gcc/|g" Makefile
perl -pi -e "s|-m32|-m64|g" Makefile
perl -pi -e "s|__i386__|__x86_64__|g" Makefile
%endif

make \
    BINDIR=%{_libdir}/ssh \
    CDEBUGFLAGS="%{optflags}" \
    CXXDEBUGFLAGS="%{optflags}"
    
# For some reason the x11-ssh-askpass.1.html file is not created on 10.0/10.1  
# x86_64, so we just do it manually here... (oden)
rm -f x11-ssh-askpass.1x.html x11-ssh-askpass.1x-html
rman -f HTML < x11-ssh-askpass._man > x11-ssh-askpass.1x-html && \
mv -f x11-ssh-askpass.1x-html x11-ssh-askpass.1.html
popd
%endif

%if %{build_gnomeaskpass}
pushd contrib
make gnome-ssh-askpass2
mv gnome-ssh-askpass2 gnome-ssh-askpass
popd
%endif

%if %mdkversion >= 200710
CFLAGS="%{optflags} -fstack-protector" ./configure \
%else
CFLAGS="%{optflags}" ./configure \
%endif
    --prefix=%{_prefix} \
    --sysconfdir=%{_sysconfdir}/ssh \
    --mandir=%{_mandir} \
    --libdir=%{_libdir} \
    --libexecdir=%{_libdir}/ssh \
    --datadir=%{_datadir}/ssh \
    --with-tcp-wrappers \
    --with-pam \
    --with-default-path=%{OPENSSH_PATH} \
    --with-xauth=%{XAUTH} \
    --with-privsep-path=/var/empty \
    --without-zlib-version-check \
%if %{build_krb5}
    --with-kerberos5=%{_prefix} \
%endif
%if %{build_skey}
    --with-skey \
%endif
%if %{build_scard}
    --with-opensc \
%endif
%if %{build_ldap}
    --with-libs="-lldap -llber" \
    --with-cppflags="-DWITH_LDAP_PUBKEY -DLDAP_DEPRECATED" \
%endif
    --with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:%{_sbindir}:%{_bindir} \
    --with-libedit
%make

%install
rm -rf %{buildroot}
%{makeinstall_std}

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
%if %{build_x11askpass}
pushd x11-ssh-askpass-%{aversion}
#make DESTDIR=%{buildroot} install
#make DESTDIR=%{buildroot} install.man
#install -d %{buildroot}%{_prefix}/X11R6/lib/X11/doc/html                
#install -m0644 x11-ssh-askpass.1.html %{buildroot}%{_prefix}/X11R6/lib/X11/doc/html/ 
install -d %{buildroot}%{_libdir}/ssh
install -d %{buildroot}%{_sysconfdir}/X11/app-defaults
install -m0644 SshAskpass.ad %{buildroot}%{_sysconfdir}/X11/app-defaults/SshAskpass
install -m0755 x11-ssh-askpass %{buildroot}%{_libdir}/ssh/
install -m0644 x11-ssh-askpass.man %{buildroot}%{_mandir}/man1/x11-ssh-askpass.1
popd
%endif

install -d %{buildroot}%{_sysconfdir}/profile.d/
%if %{build_gnomeaskpass}
install -m 755 contrib/gnome-ssh-askpass %{buildroot}%{_libdir}/ssh/gnome-ssh-askpass
%endif

cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-askpass.csh <<EOF
#!/bin/csh
setenv SSH_ASKPASS %{_libdir}/ssh/ssh-askpass
EOF
cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-askpass.sh <<EOF
#!/bin/sh
export SSH_ASKPASS=%{_libdir}/ssh/ssh-askpass
EOF



install -m 755 %{SOURCE6} %{buildroot}%{_sysconfdir}/profile.d/

install -m 0755 %{SOURCE3} %{buildroot}/%{_bindir}/ssh-copy-id
chmod a+x %{buildroot}/%{_bindir}/ssh-copy-id
install -m 644 contrib/ssh-copy-id.1 %{buildroot}/%{_mandir}/man1/

# create pre-authentication directory
mkdir -p %{buildroot}/var/empty

# remove unwanted files
rm -f %{buildroot}%{_libdir}/ssh/ssh-askpass

%if !%{build_scard}
rm -f %{buildroot}%{_datadir}/ssh/Ssh.bin
%endif

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

%clean
rm -rf %{buildroot}

%pre server
%_pre_useradd sshd /var/empty /bin/true

%post server
# do some key management; taken from the initscript

KEYGEN=/usr/bin/ssh-keygen
RSA1_KEY=/etc/ssh/ssh_host_key
RSA_KEY=/etc/ssh/ssh_host_rsa_key
DSA_KEY=/etc/ssh/ssh_host_dsa_key

do_rsa1_keygen() {
	if [ ! -s $RSA1_KEY ]; then
		echo -n "Generating SSH1 RSA host key... "
		if $KEYGEN -q -t rsa1 -f $RSA1_KEY -C '' -N '' >&/dev/null; then
			chmod 600 $RSA1_KEY
			chmod 644 $RSA1_KEY.pub
			echo "done"
			echo
		else
			echo "failed"
			echo
			exit 1
		fi
	fi
}

do_rsa_keygen() {
	if [ ! -s $RSA_KEY ]; then
		echo "Generating SSH2 RSA host key... "
		if $KEYGEN -q -t rsa -f $RSA_KEY -C '' -N '' >&/dev/null; then
			chmod 600 $RSA_KEY
			chmod 644 $RSA_KEY.pub
			echo "done"
			echo
		else
			echo "failed"
			echo
			exit 1
		fi
	fi
}

do_dsa_keygen() {
	if [ ! -s $DSA_KEY ]; then
		echo "Generating SSH2 DSA host key... "
		if $KEYGEN -q -t dsa -f $DSA_KEY -C '' -N '' >&/dev/null; then
			chmod 600 $DSA_KEY
			chmod 644 $DSA_KEY.pub
			echo "done"
			echo
		else
			echo "failed"
			echo
			exit 1
		fi
	fi
}

do_rsa1_keygen
do_rsa_keygen
do_dsa_keygen
%_post_service sshd

%preun server
%_preun_service sshd

%postun server
%_postun_userdel sshd

%if %{build_x11askpass}
%post askpass
update-alternatives --install %{_libdir}/ssh/ssh-askpass ssh-askpass %{_libdir}/ssh/x11-ssh-askpass 10
update-alternatives --install %{_bindir}/ssh-askpass bssh-askpass %{_libdir}/ssh/x11-ssh-askpass 10

%postun askpass
[ $1 = 0 ] || exit 0
update-alternatives --remove ssh-askpass %{_libdir}/ssh/x11-ssh-askpass
update-alternatives --remove bssh-askpass %{_libdir}/ssh/x11-ssh-askpass
%endif

%if %{build_gnomeaskpass}
%post askpass-gnome
update-alternatives --install %{_libdir}/ssh/ssh-askpass ssh-askpass %{_libdir}/ssh/gnome-ssh-askpass 20
update-alternatives --install %{_bindir}/ssh-askpass bssh-askpass %{_libdir}/ssh/gnome-ssh-askpass 20

%postun askpass-gnome
[ $1 = 0 ] || exit 0
update-alternatives --remove ssh-askpass %{_libdir}/ssh/gnome-ssh-askpass
update-alternatives --remove bssh-askpass %{_libdir}/ssh/gnome-ssh-askpass
%endif

%triggerpostun server -- openssh-server < 3.8p1
if grep -qE "^\W*auth\W+\w+\W+.*pam_(ldap|winbind|mysql)" /etc/pam.d/system-auth /etc/pam.d/sshd; then
   perl -pi -e 's|^#UsePAM no|UsePAM yes|' /etc/ssh/sshd_config
fi

%files
%defattr(-,root,root)
%doc ChangeLog OVERVIEW README* INSTALL CREDITS LICENCE TODO ssh_ldap_key.pl
%if %{build_watchdog}
%doc CHANGES-openssh-watchdog openssh-watchdog.html
%endif
%if %{build_sftplog}
%doc sftplogging-installation.html
%endif
%{_bindir}/ssh-keygen
%dir %{_sysconfdir}/ssh
%{_bindir}/ssh-keyscan
%{_mandir}/man1/ssh-keygen.1*
%{_mandir}/man1/ssh-keyscan.1*
%{_mandir}/man8/ssh-keysign.8*
%{_libdir}/ssh/ssh-keysign
%if %{build_scard}
%dir %{_datadir}/ssh
%{_datadir}/ssh/Ssh.bin
%endif

%files clients
%defattr(-,root,root)
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
%attr(0755,root,root) %{_sysconfdir}/profile.d/ssh-client.sh

%files server
%defattr(-,root,root)
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/sshd
%{_sbindir}/sshd
%dir %{_libdir}/ssh
%{_libdir}/ssh/sftp-server
%{_mandir}/man5/sshd_config.5*
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
%defattr(-,root,root)
%attr(0755,root,root) %{_sysconfdir}/profile.d/90ssh-askpass.*

%if %{build_x11askpass}
%files askpass
%defattr(-,root,root)
%doc x11-ssh-askpass-%{aversion}/README
%doc x11-ssh-askpass-%{aversion}/ChangeLog
%doc x11-ssh-askpass-%{aversion}/SshAskpass*.ad
%doc x11-ssh-askpass-%{aversion}/x11-ssh-askpass.1.html
%{_libdir}/ssh/x11-ssh-askpass
%{_sysconfdir}/X11/app-defaults/SshAskpass
#%{_prefix}/X11R6/lib/X11/doc/html/x11-ssh-askpass.1.html
%{_mandir}/man1/x11-ssh-askpass.1*
%endif

%if %{build_gnomeaskpass}
%files askpass-gnome
%defattr(-,root,root)
%{_libdir}/ssh/gnome-ssh-askpass
%endif



