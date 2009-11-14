###########################################
package Net::SSH::AuthorizedKey;
###########################################
our @accessors = qw(options key type 
                    encryption);
our %accessors = map { $_ => 1 } @accessors;
__PACKAGE__->make_accessor( $_ ) for @accessors;

use strict;
use warnings;
use Log::Log4perl qw(:easy);

# There are options that carry values (like command="ls") and 
# binary options that are either set or unset. To set a binary
# option, use
#
#     $self->option_set("no_agent_forwarding")
#
# (no value parameter) and to set an option that carries a value, provide
# the value as the second parameter:
#
#     $self->option_set("command", "ls");
#
# To retrieve the value of an option, use
#
#      $onoff = $self->option_get("no_agent_forwarding")
#
# for a binary option, which returns 1 if it's set and undef
# if it isn't. To retrieve the value of an option that carries
# a value, use 
#
#     $command = $self->option_get("command");
#
# respecitively.

###########################################
sub option_set {
###########################################
    my($self, $key, $value) = @_;

    $key = lc $key;

    if(defined $value) {
        $self->{options}->{$key} = $value;
    } else {
        $self->{options}->{$key} = \undef;
    }

    return $self->option_get( $key );
}

###########################################
sub option_get {
###########################################
    my($self, $key) = @_;


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

=head1 LEGALESE

Copyright 2005-2009 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
