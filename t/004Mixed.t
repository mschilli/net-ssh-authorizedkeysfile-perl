######################################################################
# Test suite for Net::SSH::AuthorizedKeysFile
# by Mike Schilli <m@perlmeister.com>
######################################################################

use warnings;
use strict;
use Sysadm::Install qw(:all);

#use Log::Log4perl qw(:easy);
#Log::Log4perl->easy_init($DEBUG);

use Test::More tests => 5;
BEGIN { use_ok('Net::SSH::AuthorizedKeysFile') };

my $tdir = "t";
$tdir = "../t" unless -d $tdir;
my $cdir = "$tdir/canned";

use Net::SSH::AuthorizedKeysFile;

my $ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-mixed.txt");

my @keys = $ak->keys();

is($keys[0]->email(), 'foo@bar.com', "email1");
is($keys[1]->email(), 'bar@foo.com', "email2");
is($keys[2]->email(), 'quack@schmack.com', "email3");

my $org_data = slurp("$cdir/ak-mixed.txt"); 
$org_data =~ s/^\s*#.*\n//mg;

is($ak->as_string(), $org_data, "write-back");
