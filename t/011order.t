#
# Test cases for ssh2 keys
#
use Net::SSH::AuthorizedKey;
use Net::SSH::AuthorizedKey::SSH2;
use Test::More;
use Log::Log4perl qw(:easy);

# Log::Log4perl->easy_init($DEBUG);

plan tests => 2;

my $t2key = 'ssh-rsa AAAAB3NzaCKK7696k6U= bar@foo.ms.com';

  # specific
my $pk = Net::SSH::AuthorizedKey::SSH2->parse($t2key);

$pk->option( "no-port-forwarding", 1 );
$pk->option( "no-agent-forwarding", 1 );
$pk->option( "no-x11-forwarding", 1 );
$pk->option( "no-pty", 1 );
$pk->option( "no-user-rc", 1 );
$pk->option( "command", "blah blah" );
$pk->option( "environment", "moo" );
$pk->option( "from", "here,there" );
$pk->option( "permitopen", "oink" );
$pk->option( "tunnel", "yes, please" );

like $pk->as_string(), qr/no-port-forwarding,no-agent-forwarding,no-x11-forwarding,no-pty,no-user-rc,command="blah blah",environment="moo",from="here,there",permitopen="oink",tunnel="yes, please" ssh-rsa/, "options in order";

$pk->option_delete( "command");
$pk->option_delete( "no-pty");

like $pk->as_string(), qr/no-port-forwarding,no-agent-forwarding,no-x11-forwarding,no-user-rc,environment="moo",from="here,there",permitopen="oink",tunnel="yes, please" ssh-rsa/, "options in order after delete";

