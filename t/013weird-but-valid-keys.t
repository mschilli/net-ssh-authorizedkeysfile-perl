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
    my($key, $comment) = split / ## /, $_;

    chomp $comment;

    my $ssh = Net::SSH::AuthorizedKey->parse($key);

    ok defined $ssh, "$comment";
}

__DATA__
ecdsa-sha2-9UzNcgwTlEnSCECZa7V1mw== AAAAB3NzaC1yc2EU= foo ## draft 6 of RFC5656, is Base64(MD5(DER(OID))).
