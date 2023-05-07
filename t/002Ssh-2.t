######################################################################
# Test suite for Net::SSH::AuthorizedKeysFile (ssh-2)
# by Mike Schilli <m@perlmeister.com>
######################################################################

use warnings;
use strict;
use File::Temp qw(tempfile);
use Log::Log4perl qw(:easy);
use File::Copy;
# Log::Log4perl->easy_init($DEBUG);

use Test::More tests => 59;
BEGIN { use_ok('Net::SSH::AuthorizedKeysFile') };

my $tdir = "t";
$tdir = "../t" unless -d $tdir;
my $cdir = "$tdir/canned";

use Net::SSH::AuthorizedKeysFile;

my $ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-ssh2.txt");
$ak->read();

my @keys = $ak->keys();

is($keys[0]->type(), "ssh-2", "type");
is($keys[1]->type(), "ssh-2", "type");

is($keys[0]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj234", "key");
is($keys[1]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj234", "key");

is($keys[0]->email(), 'foo@bar.com', "key");
is($keys[1]->email(), 'bar@foo.com', "key");

# modify a ssh-2 key
my($fh, $filename) = tempfile();
copy "$cdir/ak-ssh2.txt", $filename;
$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-ssh2.txt");
$ak->read();

$ak = Net::SSH::AuthorizedKeysFile->new(file => $filename);
$ak->read();

@keys = $ak->keys();

$keys[0]->key("123");
is($keys[0]->key(), "123", "modified key");
$ak->save();

$ak = Net::SSH::AuthorizedKeysFile->new(file => $filename);
$ak->read();
is($keys[0]->key(), "123", "modified key");
is($keys[1]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj234", "unmodified key");

# ECDSA support

$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-ecdsa.txt");
$ak->read();

@keys = $ak->keys();

is($keys[0]->type(), "ssh-2", "type"); # ecdsa-sha2-nistp521
is($keys[1]->type(), "ssh-2", "type");

is($keys[0]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj234", "key");
is($keys[1]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj235", "key");

# Ed25519 support

$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-ed25519.txt");
$ak->read();

@keys = $ak->keys();

is($keys[0]->type(), "ssh-2", "type"); # ed25519

is($keys[0]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj234", "key");
is($keys[1]->key(), "AAAAAlkj2lkjalsdfkjlaskdfj235", "key");

# Bulk key testing
my @keytype = (
 'ecdsa-sha2-nistp256',
 'ecdsa-sha2-nistp384',
 'ecdsa-sha2-nistp521',
 # SK
 'sk-ecdsa-sha2-nistp256',
 'sk-ssh-ed25519',
 # Cert, no SK
 'ecdsa-sha2-nistp256-cert-v01',
 'ssh-dss-cert-v01',
 'ssh-ed25519-cert-v01',
 'ssh-rsa-cert-v01',
 ## SK + cert
 'sk-ecdsa-sha2-nistp256-cert-v01',
 'sk-ssh-ed25519-cert-v01',
 # Alt cases:
 'ecdsa-sha2-secp384r1',
 'ecdsa-sha2-1.3.132.0.34',
 'x509v3-ecdsa-sha2-nistp384',
);

foreach my $kt (@keytype) {
	my $f = sprintf("$cdir/ak-ssh2-%s.txt", $kt);
	#print STDERR "$f\n";
	my $ak = Net::SSH::AuthorizedKeysFile->new(file => $f);
	$ak->read();
	my @keys = $ak->keys();
	is(scalar(@keys) > 0, 1, "non-zero $kt");
	is($keys[0]->type(), "ssh-2", "type $kt");
	my $enc = $keys[0]->encryption();
	$enc =~ s/\@openssh.com$//g; # make testing easier
	is($enc, $kt, "encryption $kt");
}
