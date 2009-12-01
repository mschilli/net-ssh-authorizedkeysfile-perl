###########################################
package Net::SSH::AuthorizedKeysFile;
###########################################
use Log::Log4perl qw(:easy);
use Text::ParseWords;
use Net::SSH::AuthorizedKey;
use Net::SSH::AuthorizedKey::SSH1;
use Net::SSH::AuthorizedKey::SSH2;

our $VERSION = "0.11";

###########################################
sub new {
###########################################
    my($class, @options) = @_;

    my $self = {
        file   => "$ENV{HOME}/.ssh/authorized_keys",
        keys   => [],
        strict => 0,
        @options,
    };

    bless $self, $class;

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
    my($self, $file) = @_;

    $self->{file} = $file if defined $file;

    my $line = 0;

    DEBUG "Reading in $self->{file}";

    open FILE, "<$self->{file}" or LOGDIE "Cannot open $self->{file}";

    while(<FILE>) { 

        chomp;

        s/^\s+//;     # Remove leading blanks
        s/\s+$//;     # Remove trailing blanks
        next if /^$/; # Ignore empty lines
        next if /^#/; # Ignore comment lines
        $line++;

        DEBUG "Analyzing line [$_]";

        my $line_string = $_;

        my $pk = Net::SSH::AuthorizedKey->parse( $line_string );

        if($pk and $pk->sanity_check()) {
            push @{ $self->{keys} }, $pk;
        } else {
            WARN "Key [$line_string] failed sanity check -- ignored";
            if($self->{strict}) {
                WARN "Strict mode on: Abort";
                if(defined $pk) {
                    $self->error( $pk->error() );
                } else {
                    $self->error( "Invalid line: [$line_string] " .
                                  "rejected by all parsers" );
                }
                close FILE;
                return undef;
            }
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
    my($self, $file) = @_;

    if(!defined $file) {
        $file = $self->{file};
    }

    if(! open FILE, ">$file") {
        $self->error("Cannot open $file ($!)");
        WARN $self->error();
        return undef;
    }

    print FILE $self->as_string();
    close FILE;
}

###########################################
sub error {
###########################################
    my($self, $text) = @_;

    if(defined $text) {
        $self->{error} = $text;
    }

    return $self->{error};
}

1;

__END__

=head1 NAME

Net::SSH::AuthorizedKeysFile - Read and modify ssh's authorized_keys files

=head1 SYNOPSIS

    use Net::SSH::AuthorizedKeysFile;

        # Reads $HOME/.ssh/authorized_keys by default
    my $akf = Net::SSH::AuthorizedKeysFile->new();

    $akf->read("authorized_keys");

        # Iterate over entries
    for my $key ($akf->keys()) {
        print $key->as_string(), "\n";
    }

        # Modify entries:
    for my $key ($akf->keys()) {
        $key->option("from", 'quack@quack.com');
        $key->keylen(1025);
    }
        # Save changes back to $HOME/.ssh/authorized_keys
    $akf->save() or die "Cannot save";

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

Normally, the C<read> method described below will just silently ignore 
faulty lines and only gobble up keys that either one of the two parsers
accepts. If you want it to be stricter, set

    Net::SSH::AuthorizedKeysFile->new( file   => "authkeys_file",
                                       strict => 1 );

and read will immediately abort after the first faulty line.

=item C<read>

Reads in the file defined by new(). By default, strict mode is off and 
read() will silently ignore faulty lines. If it's on (see new() above),
read() will immediately abort after the first faulty line. A textual
description of the last error will be available via error().

=item C<keys>

Returns a list of Net::SSH::AuthorizedKey objects. Methods are described in
L<Net::SSH::AuthorizedKey>.

=item C<as_string>

String representation of all keys, ultimately the content that gets
written out when calling the C<save()> method. 
Note that comments from the original file are lost.

=item C<save>

Write changes back to the authorized_keys file using the as_string()
method described above. Note that comments from the original file are lost.
Optionally takes a file
name parameter, so calling C<$akf-E<gt>save("foo.txt")> will save the data
in the file "foo.txt" instead of the file the data was read from originally.
Returns 1 if successful, and undef on error. In case of an error, error()
contains a textual error description.

=item C<error>

Description of last error that occurred.

=back

=head1 LEGALESE

Copyright 2005-2009 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
