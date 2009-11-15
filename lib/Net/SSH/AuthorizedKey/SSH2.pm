###########################################
package Net::SSH::AuthorizedKey::SSH2;
###########################################
use strict;
use warnings;
use base qw(Net::SSH::AuthorizedKey::Base);
use Log::Log4perl qw(:easy);

###########################################
sub new {
###########################################
    my($class, %options) = @_;

    return $class->SUPER::new( type => "ssh-1" );
}

###########################################
sub as_string {
###########################################
    my($self) = @_;

    my $string = $self->options_as_string();
    $string .= " " if length $string;

    $string .= "$self->{encryption} $self->{key} $self->{email}";

    return $string;
}

###########################################
sub parse {
###########################################
    my($self, $string) = @_;

    DEBUG "Parsing key [$string]";

    # Multi-line:
    #    Comment: "rsa-key-20090703"
    # or single line:
    #    tunnel="0",command="sh /etc/netstart tun0" ssh-rsa AAAA...

    if($string =~ /\A\s*\Z/s) {
        WARN "Empty multi-line string ignored";
        return undef;
    }

      # check for a newline followed by a character to determine
      # if it's multi-line or single-line.
    if($string =~ /\n./) {
        return $self->parse_multi_line( $string );
    }

    return $self->parse_single_line( $string );
}

###########################################
sub parse_multi_line {
###########################################
    my($self, $string) = @_;

    my @fields = ();

    while($string =~ s/^(.*):\s+(.*)//gm) {
        my($field, $value) = ($1, $2);
          # remove quotes
        $value =~ s/^"(.*)"$/$1/;
        push @fields, $field, $value;
        my $lcfield = lc $field;

        if( $self->accessor_exists( $lcfield ) ) {
            $self->$lcfield( $value );
        } else {
            WARN "Ignoring unknown field '$field'";
        }
    }

      # Rest is the key, split across several lines
    $string =~ s/\n//g;
    $self->key( $string );
    $self->type( "ssh-2" );

      # Comment: "rsa-key-20090703"
    if($self->comment() =~ /\b(.*?)-key/) {
        $self->encryption( "ssh-" . $1 );
    } elsif( ! $self->{strict} ) {
        WARN "Unknown encryption [", $self->comment(), 
             "] fixed to ssh-rsa"; 
        $self->encryption( "ssh-rsa" );
    }
}

###########################################
sub parse_single_line {
###########################################
    my($self, $string) = @_;

    die "Whoa, not implemented!";
}

###########################################
sub sanity_check {
###########################################
    my($self) = @_;

    my @fields = qw(key);

    for my $field (@fields) {
        if(! defined $self->$field()) {
            WARN "Sanity check failed '$field' requirement";
            return undef;
        }
    }
    return 1;
}

1;

__END__

=head1 NAME

Net::SSH::AuthorizedKey - Holds a single line of the authorized_keys file

=head1 SYNOPSIS

    use Net::SSH::AuthorizedKey;

    my $akf = Net::SSH::AuthorizedKey->new(
        options  => { from => 'foo@bar.com', "no-agent-forwarding" },
        key      => "123....890",
        keylen   => 1024,
        exponent => 35,
        type     => "ssh-1",
        email    => 'issuer@issuer.com',
    );

=head1 DESCRIPTION

Net::SSH::AuthorizedKey objects holds key lines from ssh's authorized_keys
files. They just provide getter/setter methods.

=head1 METHODS

=over 4

=item C<option>

Get/set an option. Note that options can be either binary or carry a string:

        # Set "no-agent-forwarding" option
    $ak->option("no-agent-forwarding", 1);

        # Check if no-agent-forwarding option is set
    if($ak->option("no-agent-forwarding")) {
        # ...
    }

        # Set the from option to 'from="a@b.com"'
    $ak->option(from => 'a@b.com');

        # Get the value of the 'from' option
    my $val = $ak->option("from");

=item C<option_delete>

Remove an option completely. C<$ak-E<gt>option_delete("from")> will remove
the C<from> option from the key meta info.

=item C<type>

Type of ssh key, either C<"ssh-1"> or C<"ssh-2">.

=item C<email>

Email address of the person who created the key. (Different from 
the "from" option).

=item C<key>

Public key, either a long number (ssh-1) or a line of alphanumeric
characters.

=item C<keylen>

Length of the key in bit (e.g. 1024).

=item C<exponent>

Two-digit number in front of the key in ssh-1 keys.

=back

Calling a method will return C<undef> if the corresponding entry doesn't
exist in the key meta data.

=head1 LEGALESE

Copyright 2005 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
