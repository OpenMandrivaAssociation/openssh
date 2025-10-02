%bcond_with skey
%bcond_without krb5
%bcond_without gnomeaskpass
%bcond_with audit
%bcond_without libedit

%define OPENSSH_PATH "/usr/local/bin:/bin:%{_bindir}"
%define XAUTH %{_bindir}/xauth

Summary:	OpenSSH free Secure Shell (SSH) implementation
Name:		openssh
Version:	10.0p1
Release:	4
License:	BSD
Group:		Networking/Remote access
Url:		https://www.openssh.com/
Source0:	http://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/%{name}-%{version}.tar.gz
Source4:	sshd.tmpfiles
Source12:	ssh_ldap_key.pl
Source15:	ssh-avahi-integration
Source17:	sshd.pam
Source18:	sshd.service
Source22:	sshd-keygen
Source23:	sshd.socket
Source24:	sshd@.service
Source25:	sshd-keygen.service
Source26:	sshd.sysconfig
Source27:	ssh-agent.service
Source28:	openssh.sysusers
Patch1:		openssh-omdv_conf.patch
# Without this, any connection attempt results in
# input_userauth_error: bad message during authentication: type 95
# This is probably a workaround for a bug in openssl.
# https://github.com/openssl/openssl/issues/13064
#Patch2:		openssh-8.4p1-broken-chacha20.patch
# Runtime version of openssl mismatching buildtime version may
# be worth logging as a debug message, but certainly not aborting
# sshd on startup.
# If the ABI breaks, the soname changes and the library won't be
# opened anyway. No incompatible changes between e.g. 3.1 and 3.2.
Patch3:		openssh-9.5p1-dont-freak-out-on-openssl-mismatch.patch

#https://bugzilla.mindrot.org/show_bug.cgi?id=1402
# https://bugzilla.redhat.com/show_bug.cgi?id=1171248
# record pfs= field in CRYPTO_SESSION audit event
Patch200:	openssh-7.6p1-audit.patch
# Audit race condition in forked child (#1310684)
Patch201:	openssh-7.1p2-audit-race-condition.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1893 (WONTFIX)
Patch604:	openssh-6.6p1-keyperm.patch
#(drop?) https://bugzilla.mindrot.org/show_bug.cgi?id=1925
Patch606:	openssh-5.9p1-ipv6man.patch
#?
Patch607:	openssh-5.8p2-sigpipe.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1789
Patch609:	openssh-7.2p2-x11.patch

#?
Patch702:	openssh-5.1p1-askpass-progress.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=198332
Patch703:	openssh-4.3p2-askpass-grab-info.patch

# GSSAPI Key Exchange (RFC 4462 + draft-ietf-curdle-gss-keyex-sha2-08)
# from https://github.com/openssh-gsskex/openssh-gsskex/tree/fedora/master
# FIXME re-enable once ported to 9.x
#Patch800:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-8.0p1-gssapi-keyex.patch
#http://www.mail-archive.com/kerberos@mit.edu/msg17591.html
# FIXME re-enable once ported to 9.x
#Patch801:	openssh-6.6p1-force_krb.patch
# add new option GSSAPIEnablek5users and disable using ~/.k5users by default (#1169843)
# CVE-2014-9278
# FIXME re-enable once ported to 9.x
#Patch802:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-6.6p1-GSSAPIEnablek5users.patch
# Improve ccache handling in openssh (#991186, #1199363, #1566494)
# https://bugzilla.mindrot.org/show_bug.cgi?id=2775
# FIXME re-enable once ported to 9.x
#Patch804:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-7.7p1-gssapi-new-unique.patch
# Respect k5login_directory option in krk5.conf (#1328243)
# FIXME re-enable once ported to 9.x
#Patch805:	openssh-7.2p2-k5login_directory.patch

#https://bugzilla.mindrot.org/show_bug.cgi?id=1780 (rediffed)
#Patch901:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-6.6p1-kuserok.patch
# Use tty allocation for a remote scp (#985650)
Patch906:	openssh-6.4p1-fromto-remote.patch
# log via monitor in chroots without /dev/log (#2681)
# FIXME re-enable when ported to 9.x
#Patch918:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-6.6.1p1-log-in-chroot.patch
# scp file into non-existing directory (#1142223)
Patch919:	openssh-6.6.1p1-scp-non-existing-directory.patch
# apply upstream patch and make sshd -T more consistent (#1187521)
Patch922:	openssh-6.8p1-sshdT-output.patch
# Add sftp option to force mode of created files (#1191055)
Patch926:	openssh-6.7p1-sftp-force-permission.patch
# Move MAX_DISPLAYS to a configuration option (#1341302)
Patch944:	openssh-7.3p1-x11-max-displays.patch
# Help systemd to track the running service
Patch948:	openssh-7.4p1-systemd.patch
# Fix typo in sandbox code; missing header for s390
Patch950:	openssh-7.5p1-sandbox.patch
# https://github.com/Jakuje/openssh-portable/commits/jjelen-pkcs11
# git show > ~/devel/fedora/openssh/openssh-8.0p1-pkcs11-uri.patch
Patch951:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-8.0p1-pkcs11-uri.patch
# Unbreak scp between two IPv6 hosts (#1620333)
Patch953:	openssh-7.8p1-scp-ipv6.patch
# Mention crypto-policies in manual pages (#1668325)
Patch962:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-8.0p1-crypto-policies.patch
# Use OpenSSL KDF (#1631761)
Patch964:	openssh-8.0p1-openssl-kdf.patch
# sk-dummy.so built with -fvisibility=hidden does not work
Patch965:	openssh-8.2p1-visibility.patch
# Do not break X11 without IPv6
Patch966:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-8.2p1-x11-without-ipv6.patch
# https://bugzilla.mindrot.org/show_bug.cgi?id=3213
Patch969:	https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/openssh-8.4p1-debian-compat.patch
# Don't spew a fatal error if the runtime openssl version doesn't match
# the buildtime version. It's been a LONG time since openssl broke the
# ABI badly enough to warrant this.
# A warning is (more than) sufficient.
Patch970:	openssh-9.1p1-openssl-mismatch-nonfatal.patch

BuildRequires:	groff-base
BuildRequires:	pam-devel
BuildRequires:	pkgconfig(systemd)
BuildRequires:	pkgconfig(openssl)
BuildRequires:	pkgconfig(zlib)
BuildRequires:	pkgconfig(com_err)
BuildRequires:	pkgconfig(libnsl)
BuildRequires:	pkgconfig(p11-kit-1)
%if %{with skey}
BuildRequires:	skey-devel
%endif
%if %{with krb5}
BuildRequires:	krb5-devel
%endif
%if %{with gnomeaskpass}
BuildRequires:	pkgconfig(gtk+-3.0)
%endif
%if %{with audit}
BuildRequires:	audit-devel
%endif
%if %{with libedit}
BuildRequires:	pkgconfig(libedit)
BuildRequires:	pkgconfig(ncurses)
%endif
BuildConflicts:	libgssapi-devel
BuildRequires:	pkgconfig(systemd)
BuildRequires:	systemd-macros
%systemd_ordering
Obsoletes:	openssh-ldap <= 8.4p1
Obsoletes:	ssh < 7.1
Provides:	ssh = 7.1
Recommends:	p11-kit

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

You can build %{name} with some conditional build switches;

(ie. use with rpm --rebuild):

--with[out] skey         smartcard support (disabled)
--with[out] krb5         kerberos support (enabled)
--with[out] gnomeaskpass Gnome ask pass support (disabled)
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
Requires(post):	%{name} = %{EVRD}
Requires:	%{name}-clients = %{EVRD}
Requires:	pam >= 0.74
%systemd_requires
%if %{with skey}
Requires:	skey
%endif
Provides:	ssh-server
Provides:	sshd

%description server
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
Requires(pre):	chkconfig
Provides:	%{name}-askpass
Provides:	ssh-askpass
Provides:	ssh-extras

%description askpass-gnome
This package contains the GNOME passphrase dialog.
%endif

%prep
%setup -q
%patch 1 -p1 -b .mdkconf

%patch 604 -p1 -b .keyperm
%patch 606 -p1 -b .ipv6man
%patch 607 -p1 -b .sigpipe
%patch 609 -p1 -b .x11
#patch702 -p1 -b .progress # this uses gtk2
%patch 703 -p1 -b .grab-info

%patch 906 -p1 -b .fromto-remote
%patch 919 -p1 -b .scp
%patch 922 -p1 -b .sshdt
%patch 926 -p1 -b .sftp-force-mode
# FIXME reenable once ported to 9.x
#patch944 -p1 -b .x11max
%patch 948 -p1 -b .systemd
%patch 950 -p1 -b .sandbox
# FIXME reenable once ported to 9.x
#patch951 -p1 -b .pkcs11-uri
%patch 953 -p1 -b .scp-ipv6
# FIXME reenable once ported to 9.x
#patch962 -p1 -b .crypto-policies
%patch 964 -p1 -b .openssl-kdf
%patch 965 -p1 -b .visibility
%patch 966 -p1 -b .x11-ipv6
# FIXME reenable once ported to 9.x
#patch969 -p0 -b .debian
%patch 970 -p1 -b .nonfatalopensslver~

%if %{with audit}
%patch 200 -p1 -b .audit
%patch 201 -p1 -b .audit-race
%endif

install %{SOURCE12} .

install -m 0644 %{SOURCE17} sshd.pam

# fix attribs
chmod 644 ChangeLog OVERVIEW README* INSTALL CREDITS LICENCE TODO ssh_ldap_key.pl

# http://qa.mandriva.com/show_bug.cgi?id=22957
sed -i -e "s|_OPENSSH_PATH_|%{OPENSSH_PATH}|g" sshd_config

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
	--with-sandbox=seccomp_filter \
	--with-systemd \
	--with-default-pkcs11-provider=yes \
%if %{with krb5}
	--with-kerberos5=%{_prefix} \
%endif
%if %{with skey}
	--with-skey \
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

%make_build

%if %{with gnomeaskpass}
pushd contrib
    make gnome-ssh-askpass3 CC="%__cc %optflags %ldflags"
    mv gnome-ssh-askpass3 gnome-ssh-askpass
popd
%endif

%install
%make_install

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

if [ -f sshd_config.out ]; then
    install -m600 sshd_config.out %{buildroot}%{_sysconfdir}/ssh/sshd_config
else
    install -m600 sshd_config %{buildroot}%{_sysconfdir}/ssh/sshd_config
fi
echo "root" > %{buildroot}%{_sysconfdir}/ssh/denyusers

if [ -f ssh_config.out ]; then
    install -m644 ssh_config.out %{buildroot}%{_sysconfdir}/ssh/ssh_config
else
    install -m644 ssh_config %{buildroot}%{_sysconfdir}/ssh/ssh_config
fi
echo "    StrictHostKeyChecking no" >> %{buildroot}%{_sysconfdir}/ssh/ssh_config

mkdir -p %{buildroot}%{_libdir}/ssh
mkdir -p -m755  %{buildroot}%{_sysconfdir}/ssh/ssh_config.d
mkdir -p -m755  %{buildroot}%{_sysconfdir}/ssh/sshd_config.d

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

cat > %{buildroot}%{_sysconfdir}/profile.d/90ssh-agent.sh <<'EOF'
# (tpg) make ssh-agent works
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR"/ssh-agent.socket
EOF

install -m 755 contrib/ssh-copy-id %{buildroot}%{_bindir}/
install -m 644 contrib/ssh-copy-id.1 %{buildroot}%{_mandir}/man1/

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

install -D -m644 %{SOURCE28} %{buildroot}%{_sysusersdir}/%{name}.conf

%post server
%systemd_post sshd.service sshd.socket
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
do_move_old_rsa() {
    if [ -f $RSA1_KEY ]; then
    	mv $RSA1_KEY.pub $RSA1_KEY.pub.old
    fi
    if [ -f $$RSA1_KEY.pub ]; then
    	mv $RSA1_KEY.pub $RSA1_KEY.pub.old
    fi
}

do_rsa_keygen() {
    if [ ! -s $RSA_KEY ]; then
	printf '%s\n' 'Generating SSH2 RSA host key... '
	if $KEYGEN -q -t rsa -f $RSA_KEY -C '' -N '' >&/dev/null; then
	    chmod 600 $RSA_KEY
	    chmod 644 $RSA_KEY.pub
	    printf '%s\n' "done"
	    printf '%s\n' ""
	else
	    printf '%s\n' "failed"
	    printf '%s\n' ""
	    exit 1
	fi
    fi
}

do_ecdsa_keygen() {
    if [ ! -s $ECDSA_KEY ]; then
	printf '%s\n' "Generating SSH2 EC DSA host key... "
	if $KEYGEN -q -t ecdsa -f $ECDSA_KEY -C '' -N '' >&/dev/null; then
	    chmod 600 $ECDSA_KEY
	    chmod 644 $ECDSA_KEY.pub
	    printf '%s\n' "done"
	    printf '%s\n' ""
	else
	    printf '%s\n' "failed"
	    printf '%s\n' ""
	    exit 1
	fi
    fi
}

do_ed25519_keygen() {
    if [ ! -s $ED25519_KEY ]; then
	printf '%s\n' "Generating SSH2 ED25519 DSA host key... "
	if $KEYGEN -q -t ed25519 -f $ED25519_KEY -C '' -N '' >&/dev/null; then
	    chmod 600 $ED25519_KEY
	    chmod 644 $ED25519_KEY.pub
	    printf '%s\n' "done"
	    printf '%s\n' ""
	else
	    printf '%s\n' "failed"
	    printf '%s\n' ""
	    exit 1
	fi
    fi
}

do_move_old_rsa
do_rsa_keygen
do_ecdsa_keygen
do_ed25519_keygen

%preun server
%systemd_preun sshd.service sshd.socket

%postun server
%systemd_postun_with_restart sshd.service

%post clients
%systemd_user_post ssh-agent.service

%preun clients
%systemd_user_preun ssh-agent.service

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
%{_bindir}/ssh-keygen
%dir %{_sysconfdir}/ssh
%{_bindir}/ssh-keyscan
%dir %{_libdir}/ssh
%attr(4711,root,root) %{_libdir}/ssh/ssh-keysign
%{_libdir}/ssh/ssh-pkcs11-helper
%doc %{_mandir}/man1/ssh-keygen.1*
%doc %{_mandir}/man1/ssh-keyscan.1*
%doc %{_mandir}/man8/ssh-keysign.8*
%doc %{_mandir}/man8/ssh-pkcs11-helper.8*

%files clients
%{_bindir}/scp
%{_bindir}/ssh
%{_bindir}/ssh-agent
%{_bindir}/ssh-add
%{_bindir}/ssh-copy-id
%{_bindir}/sftp
%dir %{_libdir}/ssh
%{_libdir}/ssh/ssh-sk-helper
%doc %{_mandir}/man1/scp.1*
%doc %{_mandir}/man1/ssh-copy-id.1*
%doc %{_mandir}/man1/ssh.1*
%doc %{_mandir}/man1/ssh-agent.1*
%doc %{_mandir}/man1/ssh-add.1*
%doc %{_mandir}/man1/sftp.1*
%doc %{_mandir}/man5/ssh_config.5*
%doc %{_mandir}/man8/ssh-sk-helper.8*
%config(noreplace) %{_sysconfdir}/ssh/ssh_config
%dir %{_sysconfdir}/ssh/ssh_config.d
%{_sysconfdir}/profile.d/90ssh-agent.sh
%{_userunitdir}/ssh-agent.service
%{_userunitdir}/default.target.wants/ssh-agent.service

%files server
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/sshd
%{_sbindir}/sshd
%{_sbindir}/sshd-keygen
%dir %{_libdir}/ssh
%{_libdir}/ssh/sftp-server
%{_libdir}/ssh/sshd-auth
%{_libdir}/ssh/sshd-session
%doc %{_mandir}/man5/sshd_config.5*
%doc %{_mandir}/man5/moduli.5*
%doc %{_mandir}/man8/sshd.8*
%doc %{_mandir}/man8/sftp-server.8*
%dir %{_sysconfdir}/ssh/sshd_config.d
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
%{_sysusersdir}/%{name}.conf

%files askpass-common
%{_sysconfdir}/profile.d/90ssh-askpass.*

%if %{with gnomeaskpass}
%files askpass-gnome
%{_libdir}/ssh/gnome-ssh-askpass
%endif
