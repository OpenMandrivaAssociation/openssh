## Do not apply any unauthorized patches to this package!
## - vdanen 05/18/01
##

# Version of watchdog patch
%define wversion 4.4p1

# Version of the hpn patch
%define hpnver 13v6

%bcond_with skey
%bcond_without krb5
%bcond_with watchdog
%bcond_without gnomeaskpass
%bcond_with ldap
%bcond_with sftpcontrol
%bcond_with hpn
%bcond_with audit
%bcond_without libedit

%define OPENSSH_PATH "/usr/local/bin:/bin:%{_bindir}"
%define XAUTH %{_bindir}/xauth

%define _disable_lto 1

Summary:	OpenSSH free Secure Shell (SSH) implementation
Name:		openssh
Version:	7.4p1
Release:	2
License:	BSD
Group:		Networking/Remote access
Url:		http://www.openssh.com/
Source0:	http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
Source1:	http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz.asc
# ssh-copy-id taken from debian, with "usage" added
Source3:	ssh-copy-id
Source4:	sshd.tmpfiles
Source5:	README.7.1p1-1.upgrade.urpmi
Source9:	README.sftpfilecontrol
# this is never to be applied by default
# http://www.sc.isc.tohoku.ac.jp/~hgot/sources/openssh-watchdog.html
Source10:	openssh-%{wversion}-watchdog.patch.tgz
Source12:	ssh_ldap_key.pl
Source15:	ssh-avahi-integration
Source17:	sshd.pam
Source18:	sshd.service
Source19:	README.3.8p1.upgrade.urpmi
Source20:	README.3.9p1-3.upgrade.urpmi
Source21:	README.hpn
Source22:	sshd-keygen
Source23:	sshd.socket
Source24:	sshd@.service
Source25:	sshd-keygen.service
Source26:	sshd.sysconfig
Source27:	ssh-agent.service
Patch1:		openssh-omdv_conf.patch
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
Patch13:	openssh-7.4p1-gssapi-canohost.patch
Patch14:	openssh-4.7p1-audit.patch
Patch17:	openssh-5.1p1-askpass-progress.patch
Patch18:	openssh-4.3p2-askpass-grab-info.patch
Patch19:	openssh-4.0p1-exit-deadlock.patch
BuildRequires:	groff-base
BuildRequires:	pam-devel
BuildRequires:	tcp_wrappers-devel
BuildRequires:	pkgconfig(openssl)
BuildRequires:	pkgconfig(zlib)
%if %{with skey}
BuildRequires:	skey-devel
%endif
%if %{with krb5}
BuildRequires:	krb5-devel
%endif
%if %{with gnomeaskpass}
BuildRequires:	pkgconfig(gtk+-3.0)
%endif
%if %{with ldap}
BuildRequires: openldap-devel >= 2.0
%endif
%if %{with audit}
BuildRequires:	audit-devel
%endif
%if %{with libedit}
BuildRequires:	pkgconfig(libedit)
BuildRequires:	pkgconfig(ncurses)
%endif
BuildConflicts:	libgssapi-devel
BuildRequires:  systemd-units
Requires(pre,post,preun,postun):	rpm-helper > 0.24
Requires:	tcp_wrappers
Obsoletes:	ssh < 7.1
Provides:	ssh = 7.1

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

%package clients
Summary:	OpenSSH Secure Shell protocol clients
Group:		Networking/Remote access
Requires:	%{name} = %{EVRD}
Provides:	ssh-clients
Provides:	sftp
Provides:	ssh

%description clients
This package includes the clients necessary to make encrypted connections
to SSH servers.

%package server
Summary:	OpenSSH Secure Shell protocol server (sshd)
Group:		System/Servers
Requires(pre,post):	%{name} = %{EVRD}
Requires:	%{name}-clients = %{EVRD}
Requires(pre):	pam >= 0.74
Requires(pre,postun,preun,postun):	rpm-helper
%if %{with skey}
Requires:	skey
%endif
Provides:	ssh-server
Provides:	sshd

%description	server
This package contains the secure shell daemon. The sshd is the server 
part of the secure shell protocol and allows ssh clients to connect to 
your host.

%package askpass-common
Summary:	OpenSSH X11 passphrase common scripts
Group:		Networking/Remote access

%description askpass-common
OpenSSH X11 passphrase common scripts.

%if %{with gnomeaskpass}
%package askpass-gnome
Summary:	OpenSSH GNOME passphrase dialog
Group:		Networking/Remote access
Requires:	%{name} = %{EVRD}
Requires:	%{name}-askpass-common
Requires(pre):	update-alternatives
Provides:	%{name}-askpass
Provides:	ssh-askpass
Provides:	ssh-extras

%description askpass-gnome
This package contains the GNOME passphrase dialog.
%endif

%prep
%setup -q -a10
%patch1 -p1 -b .mdkconf
%if %{with watchdog}
#patch -p0 -s -z .wdog < %{name}-%{wversion}-watchdog.patch
%patch4 -p1 -b .watchdog
%endif
%if %{with ldap}
sed -i 's|UsePrivilegeSeparation yes|#UsePrivilegeSeparation yes|' sshd_config
%patch6 -p1 -b .lpk
rm -f README.lpk.lpk
%define _default_patch_fuzz 3
%else
%define _default_patch_fuzz 2
%endif
%if %{with sftpcontrol}
#cat %{SOURCE8} | patch -p1 -s -z .sftpcontrol
echo "This patch is broken or needs to be updated/rediffed"; exit 1
%patch7 -p1 -b .sftplogging-v1.5
# README with license terms for this patch
install -m 0644 %{SOURCE9} .
%endif
%if %{with hpn}
echo "This patch is broken or needs to be updated/rediffed"; exit 1
%patch11 -p1 -b .hpn
%patch12 -p1 -b .peak
install %{SOURCE21} .
%endif
%patch13 -p1 -b .canohost
%if %{with audit}
%patch14 -p1 -b .audit
%endif
#patch17 -p1 -b .progress
%patch18 -p1 -b .grab-info
%patch19 -p1 -b .exit-deadlock

install %{SOURCE12} %{SOURCE19} %{SOURCE20} .

install -m 0644 %{SOURCE17} sshd.pam

# fix attribs
chmod 644 ChangeLog OVERVIEW README* INSTALL CREDITS LICENCE TODO ssh_ldap_key.pl

# http://qa.mandriva.com/show_bug.cgi?id=22957
perl -pi -e "s|_OPENSSH_PATH_|%{OPENSSH_PATH}|g" sshd_config

autoreconf -fi

%build
%ifarch %{ix86}
%define _disable_ld_no_undefined 1
%endif

%serverbuild
%configure \
	--prefix=%{_prefix} \
	--sysconfdir=%{_sysconfdir}/ssh \
	--mandir=%{_mandir} \
	--libdir=%{_libdir} \
	--libexecdir=%{_libdir}/ssh \
	--datadir=%{_datadir}/ssh \
	--disable-strip \
	--with-pam \
	--with-default-path=%{OPENSSH_PATH} \
	--with-xauth=%{XAUTH} \
	--with-privsep-path=/var/empty \
	--without-zlib-version-check \
	--with-maildir=/var/spool/mail \
	--with-sandbox=rlimit \
	--with-ssh1 \
%if %{with krb5}
	--with-kerberos5=%{_prefix} \
%endif
%if %{with skey}
	--with-skey \
%endif
%if %{with ldap}
	--with-libs="-lldap -llber" \
	--with-cppflags="-DWITH_LDAP_PUBKEY -DLDAP_DEPRECATED" \
%endif
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:%{_sbindir}:%{_bindir} \
%if %{with libedit}
	--with-libedit \
%else
	--without-libedit \
%endif
%if %{with audit}
	--with-linux-audit \
%endif

%ifarch %{ix86} %{arm}
# crisb - ftrapv causes link error (missing mulodi4) on 32-bit systems
# seems the configure code does not detect this (despite attempts)
find . -name Makefile -exec sed -i 's|-ftrapv||' {} \;
%endif

%make

%if %{with gnomeaskpass}
pushd contrib
    make gnome-ssh-askpass3 CC="%__cc %optflags %ldflags"
    mv gnome-ssh-askpass3 gnome-ssh-askpass
popd
%endif

%install
%makeinstall_std

install -d %{buildroot}%{_sysconfdir}/ssh
install -d %{buildroot}%{_sysconfdir}/pam.d/
install -d %{buildroot}%{_sysconfdir}/sysconfig
install -d %{buildroot}%{_unitdir}
install -m644 sshd.pam %{buildroot}%{_sysconfdir}/pam.d/sshd
install -m644 -D %{SOURCE4} %{buildroot}%{_tmpfilesdir}/%{name}.conf
install -m644 %{SOURCE18} %{buildroot}%{_unitdir}/sshd.service
install -m755 %{SOURCE22} %{buildroot}%{_sbindir}/sshd-keygen
install -m644 %{SOURCE23} %{buildroot}%{_unitdir}/sshd.socket
install -m644 %{SOURCE24} %{buildroot}%{_unitdir}/sshd@.service
install -m644 %{SOURCE25} %{buildroot}%{_unitdir}/sshd-keygen.service
install -m644 %{SOURCE26} %{buildroot}%{_sysconfdir}/sysconfig/sshd

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
%if %{with gnomeaskpass}
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

cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-agent.sh <<'EOF'
# (tpg) make ssh-agent works
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR"/ssh-agent.socket
EOF

install -m 0755 %{SOURCE3} %{buildroot}/%{_bindir}/ssh-copy-id
chmod a+x %{buildroot}/%{_bindir}/ssh-copy-id
install -m 644 contrib/ssh-copy-id.1 %{buildroot}/%{_mandir}/man1/

# create pre-authentication directory
mkdir -p %{buildroot}/var/empty

# remove unwanted files
rm -f %{buildroot}%{_libdir}/ssh/ssh-askpass

# avahi integration support (misc)
mkdir -p %{buildroot}%{_sysconfdir}/avahi/services/
install -m 0644 %{SOURCE15} %{buildroot}%{_sysconfdir}/avahi/services/%{name}.service

# make sure strip can touch it
chmod 755 %{buildroot}%{_libdir}/ssh/ssh-keysign

# (tpg) enable ssh-agent in userland
mkdir -p %{buildroot}%{_userunitdir}/default.target.wants
install -m644 %{SOURCE27} %{buildroot}/%{_userunitdir}/ssh-agent.service
ln -sf %{_userunitdir}/ssh-agent.service %{buildroot}%{_userunitdir}/default.target.wants/ssh-agent.service

%pre
getent group ssh_keys >/dev/null || groupadd -r ssh_keys || :

%pre server
%_pre_useradd sshd /var/empty /bin/true

%post server
# do some key management
# %{_bindir}/ssh-keygen -A
# do some key management; taken from the initscript

KEYGEN=/usr/bin/ssh-keygen
RSA1_KEY=/etc/ssh/ssh_host_key
RSA_KEY=/etc/ssh/ssh_host_rsa_key
ECDSA_KEY=/etc/ssh/ssh_host_ecdsa_key
ED25519_KEY=/etc/ssh/ssh_host_ed25519_key

# crisb move the old RSA 1 key out of the way to avoid a segfault 
# in 7.4p1
mv $RSA1_KEY ${RSA1_KEY}.old
mv $RSA1_KEY.pub $RSA1_KEY.pub.old

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

do_ecdsa_keygen() {
    if [ ! -s $ECDSA_KEY ]; then
	echo "Generating SSH2 EC DSA host key... "
	if $KEYGEN -q -t ecdsa -f $ECDSA_KEY -C '' -N '' >&/dev/null; then
	    chmod 600 $ECDSA_KEY
	    chmod 644 $ECDSA_KEY.pub
	    echo "done"
	    echo
	else
	    echo "failed"
	    echo
	    exit 1
	fi
    fi
}

do_ed25519_keygen() {
    if [ ! -s $ED25519_KEY ]; then
        echo "Generating SSH2 ED25519 DSA host key... "
        if $KEYGEN -q -t ed25519 -f $ED25519_KEY -C '' -N '' >&/dev/null; then
            chmod 600 $ED25519_KEY
            chmod 644 $ED25519_KEY.pub
            echo "done"
            echo
        else
            echo "failed"
            echo
            exit 1
        fi
    fi
}


do_rsa_keygen
do_ecdsa_keygen
do_ed25519_keygen

%postun server
%_postun_userdel sshd

%if %{with gnomeaskpass}
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
%if %{with ldap}
%doc *.schema
%endif
%if %{with watchdog}
%doc CHANGES-openssh-watchdog openssh-watchdog.html
%endif
%if %{with sftpcontrol}
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
%{_bindir}/sftp
%{_mandir}/man1/scp.1*
%{_mandir}/man1/ssh-copy-id.1*
%{_mandir}/man1/ssh.1*
%{_mandir}/man1/ssh-agent.1*
%{_mandir}/man1/ssh-add.1*
%{_mandir}/man1/sftp.1*
%{_mandir}/man5/ssh_config.5*
%config(noreplace) %{_sysconfdir}/ssh/ssh_config
%{_sysconfdir}/profile.d/90ssh-client.sh
%{_sysconfdir}/profile.d/90ssh-agent.sh
%{_userunitdir}/ssh-agent.service
%{_userunitdir}/default.target.wants/ssh-agent.service

%files server
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/sshd
%{_sbindir}/sshd
%{_sbindir}/sshd-keygen
%dir %{_libdir}/ssh
%{_libdir}/ssh/sftp-server
%{_mandir}/man5/sshd_config.5*
%{_mandir}/man5/moduli.5*
%{_mandir}/man8/sshd.8*
%{_mandir}/man8/sftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/sshd_config
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/denyusers
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/pam.d/sshd
%config(noreplace) %{_sysconfdir}/avahi/services/%{name}.service
%config(noreplace) %{_sysconfdir}/ssh/moduli
%{_unitdir}/sshd.service
%{_unitdir}/sshd.socket
%{_unitdir}/sshd-keygen.service
%{_unitdir}/sshd@.service
%dir %attr(0755,root,root) /var/empty
%{_tmpfilesdir}/openssh.conf

%files askpass-common
%{_sysconfdir}/profile.d/90ssh-askpass.*

%if %{with gnomeaskpass}
%files askpass-gnome
%{_libdir}/ssh/gnome-ssh-askpass
%endif
