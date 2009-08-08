######################################################################
# Test suite for Net::SSH::AuthorizedKeysFile
# by Mike Schilli <m@perlmeister.com>
######################################################################

use warnings;
use strict;
use Sysadm::Install qw(:all);

use Log::Log4perl qw(:easy);
#Log::Log4perl->easy_init($DEBUG);

use Test::More tests => 5;
BEGIN { use_ok('Net::SSH::AuthorizedKeysFile') };

my $tdir = "t";
$tdir = "../t" unless -d $tdir;
my $cdir = "$tdir/canned";

use Net::SSH::AuthorizedKeysFile;

my $ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/pk-ssh2.txt");

my @keys = $ak->keys();

is $keys[0]->type(), "ssh-2", "type";
is $keys[0]->comment(), "rsa-key-20090703", "comment";
like $keys[0]->key(), qr/^AAAA.*X==/, "key";

$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/pk-empty.txt");
@keys = $ak->keys();
is((scalar @keys), 0, "no keys found");
