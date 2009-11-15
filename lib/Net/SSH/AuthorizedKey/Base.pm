###########################################
package Net::SSH::AuthorizedKey::Base;
###########################################
use strict;
use warnings;
use Log::Log4perl qw(:easy);

  # Accessors common for both ssh1 and ssh2 keys
our @accessors = qw(options key type encryption);
our %accessors = map { $_ => 1 } @accessors;
__PACKAGE__->make_accessor( $_ ) for @accessors;

  # Some functions must be implemented in the subclass
do {
    no strict qw(refs);

    *{__PACKAGE__ . "::$_"} = sub {
        die "Whoa! '$_' in the virtual base class has to be ",
            " implemented by a real subclass.";
    };

} for qw(option_type as_string);

  # Options accepted by all keys
our %VALID_OPTIONS = (
    "no-port-forwarding"  => 1,
    "no-agent-forwarding" => 1,
    "no-x11-forwarding"   => 1,
    "no-pty"              => 1,
    "no-user-rc"          => 1,
    command               => "s",
    environment           => "s",
    from                  => "s",
    permitopen            => "s",
    tunnel                => "s",
);

###########################################
sub new {
###########################################
    my($class, %options) = @_;

    my $self = {
        error => "(no error)",
        %options,
    };

    bless $self, $class;
    return $self;
}

###########################################
sub option_type_global {
###########################################
    my($self, $key) = @_;

    if(exists $VALID_OPTIONS{ $key }) {
        return $VALID_OPTIONS{ $key };
    }

      # Maybe the subclass knows about it
    return $self->option_type($key);
}

###########################################
sub option {
###########################################
    my($self, $key, $value) = @_;

    $key = lc $key;

    my $option_type = $self->option_type_global($key);

    if(! defined $option_type) {
        LOGWARN "Illegal option '$key'";
        return undef;
    }

    if(defined $value) {
        if($option_type eq "s") {
            $self->{options}->{$key} = $value;
        } else {
            $self->{options}->{$key} = undef;
        }
    }

    return $self->{options}->{$key};
}

###########################################
sub option_delete {
###########################################
    my($self, $key) = @_;

    $key = lc $key;

    delete $self->{options}->{$key};
}

###########################################
sub options_as_string {
###########################################
    my($self) = @_;

    my $string = "";
    my @parts  = ();

    for my $option ( keys %{ $self->{options} } ) {
        if(defined $self->{options}->{$option}) {
            if(ref($self->{options}->{$option}) eq "ARRAY") {
                for (@{ $self->{options}->{$option} }) {
                    push @parts, option_quote($option, $_);
                }
            } else {
                push @parts, option_quote($option, $self->{options}->{$option});
            }
        } else {
            push @parts, $option;
        }
    }
    return join(',', @parts);
}

###########################################
sub option_quote {
###########################################
    my($option, $text) = @_;

    $text =~ s/([\\"])/\\$1/g;
    return "$option=\"" . $text . "\"";
}

###########################################
sub parse {
###########################################
    my($class, $string) = @_;

    # We assume whitespace and comments have been cleaned up

    if(my $key = $class->key_read( $string ) ) {
          # We found a type-1 key without options
        $key->{options} = {};
        DEBUG "Found ", $key->type(), " key: ", $key->as_string();
        return $key;
    }

    # No key found. Probably there are options in front of the key.
    # By the way: the openssh-5.x parser doesn't allow escaped 
    # backslashes (\\), so we don't either.
    (my $key_string = $string) =~ s/\s|
                                    "(\\"|.)*?"
                                   //gx;

    if(my $key = $class->key_read( $string ) ) {
          # We found a type-1 key with options
        $key->{options} = $key->options_parse( $string );
        DEBUG "Found ", $key->type(), " key: ", $key->as_string();
        return $key;
    }

    DEBUG "$class cannot parse line: $string";

    return undef;
}

##################################################
# Poor man's Class::Struct
##################################################
sub make_accessor {
##################################################
    my($package, $name) = @_;

    no strict qw(refs);

    my $code = <<EOT;
        *{"$package\\::$name"} = sub {
            my(\$self, \$value) = \@_;

            if(defined \$value) {
                \$self->{$name} = \$value;
            }
            if(exists \$self->{$name}) {
                return (\$self->{$name});
            } else {
                return "";
            }
        }
EOT
    if(! defined *{"$package\::$name"}) {
        eval $code or die "$@";
    }
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

Net::SSH::AuthorizedKey::SSH1 is a subclass of Net::SSH::AuthorizedKey,
which offers methods to control key option settings.

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

2005, Mike Schilli <m@perlmeister.com>
