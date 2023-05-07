###########################################
package Net::SSH::AuthorizedKey::SSH2;
###########################################
use strict;
use warnings;
use Net::SSH::AuthorizedKey::Base;
use base qw(Net::SSH::AuthorizedKey::Base);
use Log::Log4perl qw(:easy);

  # No additional options, only global ones
our %VALID_OPTIONS = ();

# Early versions of this code contained a complex regex that was difficult to
# maintain, and likely to become outdated. This regex prefers to have too many
# types rather than less.
#
# The IANA registry contains a partial listing of SSH parameters
# http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19
#
# What the IANA list does NOT contain is anything that is unique to clients,
# like WebAuthN, which is 'webauthn-sk-*@openssh.com'.
#
# But it could still be weird, like: ecdh-sha2-1.3.132.0.36 or ecdh-sha2-sect571k1
#
# https://www.rfc-editor.org/rfc/rfc5656.html#section-3.1:
# > "ecdsa-sha2-[identifier]" ... The string [identifier] is the identifier of
# > the elliptic curve domain parameters. The format of this string is
# > specified in Section 6.1.
#
# https://www.rfc-editor.org/rfc/rfc5656.html#section-6.3:
# > The concatenation of any so encoded ASN.1 OID specifying a set of
# > elliptic curve domain parameters with "ecdh-sha2-" is implicitly registered
# > under this specification.
#
# libassh supports larger DSA key sizes as well as SHAKE256 family.
# https://www.nongnu.org/libassh/manual/Authentication_algorithms.html
#
# Python ssh-audit tries to apply business logic about acceptable key types,
# which is outside the scope of this class. However it is useful to show the
# very obscure key types.
# https://github.com/jtesta/ssh-audit/blob/2d5a97841fa4c4411acabcc51d194af4a9ee7b32/src/ssh_audit/ssh2_kexdb.py#L175-L249
our $KEYTYPE_REGEX_CORE = qr{
	# Most keys *SHOULD* start with this prefix, but there are exceptions and
	# bugs.
	(?:ssh-)?
	(
	# SSH 1 really
	 rsa
	|rsa1
	|dsa
	# SSH 2
	# Negative lookahead used to avoid partial match
	|ecdsa-sha2-[a-z0-9.]+ #  RFC5656, section 6.1
	|ecdsa-sha2-[A-Za-z0-9+/=]+ # Draft revision 6 of RFC5656: Base64(MD5(DER(OID)))
	|dss # RFC4253
	|rsa # RFC4253
	|rsa-sha2-256 # RFC8332
	|rsa-sha2-512 # RFC8332
	|rsa-sha224 # Tectia Server SSH (will have @ssh.com suffix)
	|rsa-sha256 # Tectia Server SSH (will have @ssh.com suffix)
	|rsa-sha384 # Tectia Server SSH (will have @ssh.com suffix)
	|rsa-sha512 # Tectia Server SSH (will have @ssh.com suffix)
	|dss-sha224 # Tectia Server SSH (will have @ssh.com suffix)
	|dss-sha256 # Tectia Server SSH (will have @ssh.com suffix)
	|dss-sha384 # Tectia Server SSH (will have @ssh.com suffix)
	|dss-sha512 # Tectia Server SSH (will have @ssh.com suffix)
	|rsa2048-sha256 # https://www.rfc-editor.org/rfc/rfc6187.html#section-3.3
	|ed25519 # RFC8709
	|ed448   # RFC8709
	|xmss # OpenSSH XMSS patches, disabled by default
	|dsa2048-ssh224  # libassh
	|dsa2048-ssh256 # libassh
	|dsa3072-ssh224 # libassh
	|dsa3072-ssh256 # libassh
	|eddsa-e382-shake256 # libassh
	|eddsa-e521-shake256 # libassh
	|gost2001 # seen in python ssh-audit
	|gost2012-256
	|gost2012-512
	)
	}aax;

# These are really modifiers about how one of the above types might be wrapped.
# pgp-sign-* RFC4253
# sk- & webauthn-sk- are security keys
# spki-sign-* RFC4253
# x509v3- RFC6239, RFC6187
# x509v3-sign-* https://datatracker.ietf.org/doc/html/draft-ietf-secsh-x509-03
# spi-sign-rsa seen in ssh-audit
my $KEYTYPE_REGEX_PREFIX = qr{(?:
	 pgp-sign-
	|sk-
	|spki-sign-
	|spi-sign-
	|webauthn-sk-
	|x509v3-
	|x509v3-sign-
	)?
	}aax;

# Key types defined by RFC do not contain @.
# But the specification allows implementor-defined to be used if qualified.
#
# Optionally there is a "-cert-vNN" slug that identifies an SSH certificate.
#
# Known domains:
# - openssh.com, used for OpenSSH
# - ssh.com, used for Tectia SSH
# - libassh.org
# - libssh.org
# - tinyssh.org
my $KEYTYPE_REGEX_SUFFIX = qr{
	(?:-cert-v\d{2})?
	(?:\@[0-9a-z.]+)?
}aax;

# Put it all together
our $KEYTYPE_REGEX = qr{
  (${KEYTYPE_REGEX_PREFIX}${KEYTYPE_REGEX_CORE}${KEYTYPE_REGEX_SUFFIX})
}aax;

our @REQUIRED_FIELDS = qw(
    encryption
);

__PACKAGE__->make_accessor( $_ ) for 
   (@REQUIRED_FIELDS);

###########################################
sub new {
###########################################
    my($class, %options) = @_;

    return $class->SUPER::new( %options, type => "ssh-2" );
}

###########################################
sub as_string {
###########################################
    my($self) = @_;

    my $string = $self->options_as_string();
    $string .= " " if length $string;

    $string .= "$self->{encryption} $self->{key}";
    $string .= " $self->{email}" if length $self->{email};

    return $string;
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
sub key_read {
############################################
    my($class, $line) = @_;

    if($line !~ s/^($KEYTYPE_REGEX)\s*//) {
        DEBUG "No SSH2 keytype found";
        return undef;
    }

    my $encryption = $1;
    DEBUG "Parsed encryption $encryption";

    if($line !~ s/^(\S+)\s*//) {
        DEBUG "No SSH2 key found";
        return undef;
    }

    my $key = $1;
    DEBUG "Parsed key $key";

    my $email = $line;

    my $obj = __PACKAGE__->new();
    $obj->encryption( $encryption );
    $obj->key( $key );
    $obj->email( $email );
    $obj->comment( $email );

    return $obj;
}

###########################################
sub sanity_check {
###########################################
    my($self) = @_;

    for my $field (@REQUIRED_FIELDS) {
        if(! length $self->$field()) {
            WARN "ssh-2 sanity check failed '$field' requirement";
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

Net::SSH::AuthorizedKey::SSH2 - Net::SSH::AuthorizedKey subclass for ssh-2

=head1 DESCRIPTION

See Net::SSH::AuthorizedKey.

=head1 LEGALESE

Copyright 2005 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
