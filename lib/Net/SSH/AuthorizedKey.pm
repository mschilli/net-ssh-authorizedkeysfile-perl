###########################################
package Net::SSH::AuthorizedKey;
###########################################
use base qw(Class::Accessor);
our @accessors = qw(options key exponent keylen email type 
                             comment encryption);
our %accessors = map { $_ => 1 } @accessors;
__PACKAGE__->mk_accessors( @accessors );

use strict;
use warnings;
use Log::Log4perl qw(:easy);

our $VERSION = "0.04";

###########################################
sub accessor_exists {
###########################################
    my($self, $accessor) = @_;

    return exists $accessors{ $accessor };
}

###########################################
sub option_type {
###########################################
    my($self, $key, $value) = @_;

    if(exists $VALID_KEYWORDS{$key}) {
       return  $VALID_KEYWORDS{$key};
    } 

    if($self->{type} eq "ssh-2" and exists $VALID_SSH2_KEYWORDS{$key}) {
       return  $VALID_SSH2_KEYWORDS{$key};
    } 

    return undef;
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
it a authorized_keys string. If it recognizes either a ssh-1 or a ssh-2 type
key, it will return a Net::SSH::AuthorizedKey::SSH1 or a
Net::SSH::AuthorizedKey::SSH2 object.

=head1 LEGALESE

Copyright 2005-2009 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
