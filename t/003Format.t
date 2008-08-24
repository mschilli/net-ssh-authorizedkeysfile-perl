######################################################################
# Test suite for Net::SSH::AuthorizedKeysFile
# by Mike Schilli <m@perlmeister.com>
######################################################################

use warnings;
use strict;
use Sysadm::Install qw(:all);
use File::Temp qw(tempfile);

#use Log::Log4perl qw(:easy);
#Log::Log4perl->easy_init($DEBUG);

use Test::More tests => 17;
BEGIN { use_ok('Net::SSH::AuthorizedKeysFile') };

my $tdir = "t";
$tdir = "../t" unless -d $tdir;
my $cdir = "$tdir/canned";

use Net::SSH::AuthorizedKeysFile;

my $ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-manpage.txt");

my @keys = $ak->keys();

is($keys[0]->email(), 'user@example.net', "email");

is($keys[1]->option('from'), 
   '*.sales.example.net,!pc.sales.example.net', "from with comma");
is($keys[1]->option('From'), 
   '*.sales.example.net,!pc.sales.example.net', "from case insensitive");
is($keys[1]->comment(), 'john@example.net', "comment");

#command="dump /home",no-pty,no-port-forwarding ssh-dss AAAAC3...51R== example.net
is($keys[2]->option('command'), 'dump /home', "options including blank");
is($keys[2]->option('no-pty'), 1, "no-pty option set");
is($keys[2]->option('no-port-forwarding'), 1, "no-pty option set");
is($keys[2]->encryption(), "ssh-dss", "encryption");
is($keys[2]->email(), 'example.net', "email");

#permitopen="192.0.2.1:80",permitopen="192.0.2.2:25" ssh-dss AAAAB5...21S== 

is($keys[3]->option('permitopen')->[0], "192.0.2.1:80", "option array");
is($keys[3]->option('permitopen')->[1], "192.0.2.2:25", "option array");

#tunnel="0",command="sh /etc/netstart tun0" ssh-rsa AAAA...== jane@example.net
is($keys[4]->option('command'), "sh /etc/netstart tun0", "command with blanks");
is($keys[4]->email(), 'jane@example.net', "comment");

# Modifications
my($fh, $filename) = tempfile();

    # Modify a authkey file
cp "$cdir/ak-manpage.txt", $filename;
my $ak2 = Net::SSH::AuthorizedKeysFile->new(file => $filename);
@keys = $ak2->keys();

# Write option containing blank
$keys[4]->option('command', "waah waah waah");
$ak2->save();

    # Read in modifications
my $ak3 = Net::SSH::AuthorizedKeysFile->new(file => $filename);
@keys = $ak3->keys();

is($keys[4]->option("command"), 'waah waah waah', 
   "read back option with blanks");

# Comments with blanks
$ak = Net::SSH::AuthorizedKeysFile->new(file => "$cdir/ak-comments.txt");
@keys = $ak->keys();

# Write option containing blank
is($keys[1]->comment(), 
  'Quack Schmack quack@schmack.com', "comments with blanks");
is($keys[2]->comment(), 
  'Quack Schmack, quack@schmack.com', "comments with commas");
