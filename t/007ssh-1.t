#
# Test cases for ssh1 keys
#
use Net::SSH::AuthorizedKey;
use Net::SSH::AuthorizedKey::SSH1;
use Test::More;
use Log::Log4perl qw(:easy);

# Log::Log4perl->easy_init($DEBUG);

plan tests => 10;

my $t1key = "1042 17 123123123";

  # baseclass
my $pk = Net::SSH::AuthorizedKey::SSH1->parse($t1key);

is($pk->keylen(), "1042");
is($pk->key(), "123123123");
is($pk->exponent(), "17");
is($pk->email(), "");
is($pk->type(), "ssh-1");

  # superclass
$pk = Net::SSH::AuthorizedKey->parse($t1key);

is($pk->keylen(), "1042");
is($pk->key(), "123123123");
is($pk->exponent(), "17");
is($pk->email(), "");
is($pk->type(), "ssh-1");
