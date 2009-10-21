######################################################################
# Test suite for Net::SSH::AuthorizedKeysFile
# by Mike Schilli <m@perlmeister.com>
######################################################################

use warnings;
use strict;
use Sysadm::Install qw(:all);
use File::Temp qw(tempfile);

use Log::Log4perl qw(:easy);
#Log::Log4perl->easy_init($DEBUG);

use Test::More tests => 4;
BEGIN { use_ok('Net::SSH::AuthorizedKeysFile') };

my $tdir = "t";
$tdir = "../t" unless -d $tdir;
my $cdir = "$tdir/canned";

use Net::SSH::AuthorizedKeysFile;

my $ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-broken.txt");
my $rc = $ak->read();

is($rc, undef, "read fail on broken authorized_keys");

$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak.txt");
$rc = $ak->read();

is($rc, 1, "read ok on ok authorized_keys");

$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-broken.txt");
$rc = $ak->read();

is($rc, undef, "read fail on broken authorized_keys");
