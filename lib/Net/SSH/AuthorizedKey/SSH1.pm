###########################################
package Net::SSH::AuthorizedKey::SSH1;
###########################################
use strict;
use warnings;
use Net::SSH::AuthorizedKey::Base;
use base qw(Net::SSH::AuthorizedKey::Base);
use Log::Log4perl qw(:easy);

our @REQUIRED_FIELDS = qw(
    keylen exponent
);

__PACKAGE__->make_accessor( $_ ) for @REQUIRED_FIELDS;

  # No additional options, only global ones
our %VALID_OPTIONS = ();

###########################################
sub new {
###########################################
    my($class, %options) = @_;

    return $class->SUPER::new( %options, type => "ssh-1" );
}

###########################################
sub key_read {
############################################
    my($class, $line) = @_;

    if($line !~ s/^(\d+)\s*//) {
        DEBUG "Cannot find ssh-1 keylen";
        return undef;
    }

    my $keylen = $1;
    DEBUG "Parsed keylen: $keylen";

    if($line !~ s/^(\d+)\s*//) {
        DEBUG "Cannot find ssh-1 exponent";
        return undef;
    }

    my $exponent = $1;
    DEBUG "Parsed exponent: $exponent";

    if($line !~ s/^(\d+)\s*//) {
        DEBUG "Cannot find ssh-1 key";
        return undef;
    }

    my $key = $1;
    DEBUG "Parsed key: $key";

    my $obj = __PACKAGE__->new();
    $obj->keylen( $keylen );
    $obj->key( $key );
    $obj->exponent( $exponent );
    $obj->email( $line );
    $obj->comment( $line );

    return $obj;
}

###########################################
sub as_string {
###########################################
    my($self) = @_;

    my $string = $self->options_as_string();
    $string .= " " if length $string;

    $string .= "$self->{keylen} $self->{exponent} $self->{key}";
    $string .= " $self->{email}" if length $self->{email};

    return $string;
}

###########################################
sub sanity_check {
###########################################
    my($self) = @_;

    for my $field (@REQUIRED_FIELDS) {
        if(! length $self->$field()) {
            WARN "ssh-1 sanity check failed '$field' requirement";
            return undef;
        }
    }

    return 1;
}

###########################################
sub option_type {
###########################################
    my($self, $option) = @_;

    if(exists $VALID_OPTIONS{ $option }) {
        return $VALID_OPTIONS{ $option };
    }

    return undef;
}

1;

__END__

=head1 NAME

Net::SSH::AuthorizedKey::SSH1 - SSH version 1 public keys

=head1 SYNOPSIS

    use Net::SSH::AuthorizedKey::SSH1;

      # Either parse a string (without leading whitespace or comments):
    my $pubkey = Net::SSH::AuthorizedKey::SSH1->parse( $string );

      # ... or create an object yourself:
    my $pubkey = Net::SSH::AuthorizedKey->new(
        options  => { from                  => 'foo@bar.com', 
                      "no-agent-forwarding" => 1 },
        key      => "123....890",
        keylen   => 1024,
        exponent => 35,
        type     => "ssh-1",
    );

=head1 DESCRIPTION

Net::SSH::AuthorizedKey::SSH1 objects hold ssh version 1 public keys,
typically extracted from an authorized_keys file. 

The C<parse()> method takes a line from an authorized_keys file (leading
whitespace and comments need to be cleaned up beforehand), parses the
data, and returns a Net::SSH::AuthorizedKey::SSH1 object which offers
accessors for all relevant fields and a as_string() method to assemble 
it back together as a string.

Net::SSH::AuthorizedKey::SSH1 is a subclass of Net::SSH::AuthorizedKey::Base,
which offers methods like error() and helpers to control key option 
settings. 

=head2 FIELDS

All of the following fields are available via accessors:

=over 4

=item C<type>

Type of ssh key, usually C<"ssh-1">.

=item C<key>

Public key, either a long number (ssh-1) or a line of alphanumeric
characters.

=item C<keylen>

Length of the key in bit (e.g. 1024).

=item C<exponent>

Two-digit number in front of the key in ssh-1 authorized_keys lines.

=item C<options>

Returns a reference to a hash with options key/value pairs, listed in 
front of the key.

=back

=head1 LEGALESE

Copyright 2005-2009 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

Mike Schilli <m@perlmeister.com>
