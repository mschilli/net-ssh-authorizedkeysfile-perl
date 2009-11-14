###########################################
package Net::SSH::AuthorizedKey;
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

} for qw(option_type as_string parse);

###########################################
sub option_valid {
###########################################
    my($self, $key) = @_;

    return $self->option_type($key);
}

###########################################
sub option {
###########################################
    my($self, $key, $value) = @_;

    $key = lc $key;

    my $option_type = $self->option_type($key);

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

Net::SSH::AuthorizedKey - Virtual Base Class for SSH Public Keys

=head1 SYNOPSIS

    use Net::SSH::AuthorizedKey;

    my $key = Net::SSH::AuthorizedKey->parse( $line );

    if(defined $key) {
          # ssh-1 or ssh-2
        print "Key parsed, type is ", $key->type(), "\n";
    } else {
        die "Cannot parse key (", $key->error(), ")";
    }

=head1 DESCRIPTION

Net::SSH::AuthorizedKey is a virtual base class for ssh public keys. 
Real implementations of it are Net::SSH::AuthorizedKey::SSH1 and
Net::SSH::AuthorizedKey::SSH2. 

The only way to using it directly is by calling its parse() method, and handing
it an authorized_keys string (aka a line from an authorized_keys file). If it
recognizes either a ssh-1 or a ssh-2 type key, it will return a
Net::SSH::AuthorizedKey::SSH1 or a Net::SSH::AuthorizedKey::SSH2 object.
See their manual pages for instructions on how to use them.

=head1 NOTES FOR SUBCLASS DEVELOPERS

If you're just using Net::SSH::AuthorizedKey to parse keys, the
following section doesn't concern you. It's only relevant if you add 
new subclasses to this package, on top of what's already provided.

Net::SSH::AuthorizedKey is a (semi-)virtual base class implements 
options handling for its SSH1 and SSH2 subclasses.

SSH key lines can contain options that carry values (like command="ls") and
binary options that are either set or unset (like "no_agent_forwarding").  To
distinguish the two, and to provide a set of allowed option names, the subclass
has to implement the method option_type(), which takes an option name, and
returns

=over 4

=item *

undef if the option is not supported

=item *

"s" if the option is a "string" option that carries a value

=item *

1 if the option is a binary option

=back

The subclasses Net::SSH::AuthorizedKey::SSH1 and Net::SSH::AuthorizedKey::SSH2
are doing this already.

=head1 LEGALESE

Copyright 2005-2009 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
