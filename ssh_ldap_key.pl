#!/usr/bin/perl 

use MIME::Base64;

$file=$ARGV;

$DEFAULT_BASE = "dc=padl,dc=com";
if (defined($ENV{'LDAP_BASEDN'})) {
	$DEFAULT_BASE = $ENV{'LDAP_BASEDN'};
}

open(FH,"authorized_keys") or die "Can't open $_: $!\n";
#open(FH,$file) or die "Can't open $file: $!\n";
@list = <FH>;
close FH;
chomp @list;
foreach (@list) {
~ /(.+)\s(\w+)\@(.+$)/;
$warez=$1;
$uid=$2;
$warez64 = encode_base64("$warez");
$warez64 =~ s/\n//g;
print "dn: uid=$uid,ou=People,$DEFAULT_BASE\n";
print "changetype: modify\n";
print "add: objectClass\n";
print "objectClass: strongAuthenticationUser\n";
print "userCertificate;binary:: $warez64\n\n";
}
exit;
