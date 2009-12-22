#
# Test cases for ssh2 keys
#
use Net::SSH::AuthorizedKey;
use Net::SSH::AuthorizedKey::SSH2;
use Test::More;
use Log::Log4perl qw(:easy);
use strict;
use warnings;

# Log::Log4perl->easy_init($DEBUG);

my $offset = tell DATA;
my @data = <DATA>;
plan tests => scalar @data;

seek DATA, $offset, 0;

while(<DATA>) {
    my $key = $_;

    chomp $key;

    my $ssh = Net::SSH::AuthorizedKey->parse($_);

    ok !defined $ssh, "parsing $key";
}

__DATA__
from="*.onk.com" from="*.onk.com" 1024 37 133009991 abc@foo.com
AAAAB3NzaC1yc2EU= worp@corp.com
AAAAB3NzaC1yc2EU=
from="*.onk.com",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,1024 35 1409076329 worp@corp.com
from ="*.onk.com" 1024 35 1743547142167 abc@foo.bar.baz.com
63548219 abc@bar.baz.com
sh-rsa AAAAB3Nz
