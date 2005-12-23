###########################################
package Net::SSH::AuthorizedKeysFile;
###########################################
use Sysadm::Install qw(:all);
use Log::Log4perl qw(:easy);
use Text::ParseWords;
use Net::SSH::AuthorizedKey;

our $VERSION = "0.02";
 
###########################################
sub new {
###########################################
    my($class, @options) = @_;

    my $self = {
        file => "$ENV{HOME}/.ssh/authorized_keys",
        keys => [],
        @options,
    };

    bless $self, $class;

    $self->read();

    return $self;
}

###########################################
sub keys {
###########################################
    my($self) = @_;

    return @{$self->{keys}};
}

###########################################
sub read {
###########################################
    my($self) = @_;

    open FILE, "<$self->{file}" or LOGDIE "Cannot open $self->{file}";

    while(<FILE>) { 

        chomp;
        my @words = parse_line(qr/[,\s]/, 0, $_);

            # This should probably go into Net::SSH::AuthorizedKey::SSH[12]
        if(3 == scalar grep /^\d+$/, @words) {
            # ssh-1 key
            my($keylen, $exponent, $key, $email) = splice @words, -4;

            my %options;
            for my $option (@words) {
                my($key, $value) = split /=/, $option;

                next unless defined $key;
                $options{$key} = $value;
            }

            DEBUG "Found $keylen bit ssh-1 key";
            push @{ $self->{keys} },
                 Net::SSH::AuthorizedKey::SSH1->new({
                    type     => "ssh-1",
                    key      => $key,
                    keylen   => $keylen,
                    exponent => $exponent,
                    email    => $email,
                    options  => \%options,
                 });

        } else {
            # ssh-2 key
            my($encr, $key, $email) = @words;
            push @{ $self->{keys} },
                 Net::SSH::AuthorizedKey::SSH2->new({
                    type       => "ssh-2",
                    encryption => $encr,
                    key        => $key,
                    email      => $email,
                 });
        }
    }

    close FILE;
}

###########################################
sub as_string {
###########################################
    my($self) = @_;

    my $string = "";

    for my $key ( @{ $self->{keys} } ) {
        $string .= $key->as_string . "\n";
    }

    return $string;
}

###########################################
sub save {
###########################################
    my($self) = @_;

    blurt $self->as_string(), $self->{file};
}

1;

__END__

=head1 NAME

Net::SSH::AuthorizedKeysFile - Read and modify ssh's authorized_keys files

=head1 SYNOPSIS

    use Net::SSH::AuthorizedKeysFile;

        # Reads $HOME/.ssh/authorized_keys by default
    my $akf = Net::SSH::AuthorizedKeysFile->new();

        # Iterate over entries
    for my $key ($akf->keys()) {
        print $key->keylen(), "\n";
    }

        # Modify entries:
    for my $key ($akf->keys()) {
        $key->option("from", 'quack@quack.com');
        $key->keylen(1025);
    }
        # Save changes back to $HOME/.ssh/authorized_keys
    $akf->save();

=head1 DESCRIPTION

Net::SSH::AuthorizedKeysFile reads and modifies C<authorized_keys> files.
C<authorized_keys> files contain public keys and meta information to
be used by C<ssh> on the remote host to let users in without 
having to type their password.

=head1 METHODS

=over 4

=item C<new>

Creates a new Net::SSH::AuthorizedKeysFile object and reads in the 
authorized_keys file. The filename 
defaults to C<$HOME/.ssh/authorized_keys> unless
overridden with

    Net::SSH::AuthorizedKeysFile->new( file => "/path/other_authkeys_file" );

=item C<keys>

Returns a list of Net::SSH::AuthorizedKey objects. Methods are described in
L<Net::SSH::AuthorizedKey>.

=item C<as_string>

String representation of all keys, ultimately the content that gets
written out when calling the C<save()> method.

=item C<save>

Write changes back to the authorized_keys file.

=back

=head1 LEGALESE

Copyright 2005 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
