###########################################
package Net::SSH::AuthorizedKeysFile;
###########################################
use Sysadm::Install qw(:all);
use Log::Log4perl qw(:easy);
use Text::ParseWords;
use Net::SSH::AuthorizedKey;

our $VERSION = "0.05";

my $ssh2_regex         = qr/^ssh-/;
my $ssh2_partial_regex = qr/^\S+-(rs|ds)/;
my $ssh1_regex         = qr(^\d);
my $block_start_regex  = qr(^---*\s+begin )i;
my $block_end_regex    = qr(^---*\s+end )i;

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

    my $has_options;
    my $line = 0;

    open FILE, "<$self->{file}" or LOGDIE "Cannot open $self->{file}";

    while(<FILE>) { 

        chomp;
        s/^\s+//;     # Remove leading blanks
        s/\s+$//;     # Remove trailing blanks
        next if /^$/; # Ignore empty lines
        next if /^#/; # Ignore comment lines

        $line++;

        my $line_string = $_;

        # From the sshd manpage: 
        # Protocol 1 public keys consist of the following space-separated
        # fields: options, bits, exponent, modulus, comment. Protocol 2
        # public key consist of: options, keytype, base64-encoded key,
        # comment. The options field is optional; its presence is
        # determined by whether the line starts with a number or not (the
        # options field never starts with a number). The bits, exponent,
        # modulus, and comment fields give the RSA key for protocol
        # version 1; the comment field is not used for anything (but may
        # be convenient for the user to identify the key). For protocol
        # version 2 the keytype is "ssh-dss" or "ssh-rsa".

        if(/$block_start_regex/) {
            my $string = "";
            while(<FILE>) {
                $line++;
                if(/$block_end_regex/) {
                    last;
                }
                $string .= $_;
            }
            my $key = Net::SSH::AuthorizedKey::SSH2->new();
            $key->parse( $string );
            if( $key->sanity_check() ) {
                push @{ $self->{keys} }, $key;
            }
            next;
        } elsif( /$ssh2_regex/ or
                 (! $self->{strict} and /$ssh2_partial_regex/) ) {
            DEBUG "$ssh2_regex matched";
            $has_options = 0;
        } elsif( /$ssh1_regex/ ) {
            DEBUG "$ssh1_regex matched";
            $has_options = 0;
        } else {
            DEBUG "Found options";
            $has_options = 1;
        }
        
        my @fields = parse_line(qr/\s+/, 1, $_);

#        for(@fields) {
#            if(defined $_) {
#                print "Field: $_\n";
#            } else {
#                print "Field: *** UNDEF ***\n";
#            }
#        }

        DEBUG "Parsed fields: ", join(' ', map { "[$_]" } @fields);

        my @options = ();
        my %options = ();

        if($has_options) {
            my $options = shift @fields;
            DEBUG "Parsing options: $options" if defined $options;
            @options = parse_line(qr/,/, 0, $options);
            DEBUG "Parsed options: ", join(' ', map { "[$_]" } @options);

            for my $option (@options) {
                my($key, $value) = split /=/, $option, 2;
                $value = 1 unless defined $value;
                $value =~ s/^"(.*)"$/$1/; # remove quotes

                if(exists $options{$key}) {
                    DEBUG "Option $key already set, adding [$value] to array";
                    $options{$key} = [ $options{$key} ] if 
                        ref($options{$key}) ne "ARRAY";
                    push @{ $options{$key} }, $value;
                } else {
                    DEBUG "Setting option $key to $value";
                    $options{$key} = $value;
                }
            }
        }

        # since we kept the quotes, in all non-option fields, delete them
        # here
        for(@fields) {
            s/^"(.*)"$/$1/;
        }

        my $line_ssh_version;

          # Some jokers put dummy lines in their authorized_keys files
        $fields[0] = "" unless defined $fields[0];

        if($fields[0] =~ /$ssh1_regex/) {
            $line_ssh_version = 1;
        } elsif( $fields[0] =~ /$ssh2_regex/ or
                 (! $self->{strict} and  
                    $fields[0] =~ /$ssh2_partial_regex/) ) {
            $line_ssh_version = 2;
        } else {
            DEBUG "Neither $ssh1_regex nor $ssh2_regex matched on '$fields[0]'";
            WARN "Invalid line in $self->{file}:$line: $_";
            return undef;
        }

        if($line_ssh_version == 1) {
            # ssh-1 key
            my($keylen, $exponent, $key) = splice @fields, 0, 3;
            my $comment = join ' ', @fields;
            $comment = "" if !defined $comment;

            DEBUG "Found $keylen bit ssh-1 key";
            my $keyo = Net::SSH::AuthorizedKey::SSH1->new({
                    type     => "ssh-1",
                    key      => $key,
                    keylen   => $keylen,
                    exponent => $exponent,
                    email    => $comment,
                    comment  => $comment,
                    options  => \%options,
                 });

            if($keyo->sanity_check()) {
                push @{ $self->{keys} }, $keyo;
            } else {
                WARN "Key [$line_string] failed sanity check -- ignored";
            }

        } else {
            # ssh-2 key
            DEBUG "Found ssh-2 key: [@fields]";
            my($encr, $key) = splice @fields, 0, 2;
            my $comment = join ' ', @fields;
            $comment = "" if !defined $comment;

            my $keyo = Net::SSH::AuthorizedKey::SSH2->new({
                    type       => "ssh-2",
                    encryption => $encr,
                    key        => $key,
                    email      => $comment,
                    comment    => $comment,
                    options    => \%options,
                 });

            if($keyo->sanity_check()) {
                push @{ $self->{keys} }, $keyo;
            } else {
                WARN "Key [$line_string] failed sanity check -- ignored";
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

    blurt $self->as_string(), $file;
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
Note that comments from the original file are lost.

=item C<save>

Write changes back to the authorized_keys file using the as_string()
method described above. Note that comments from the original file are lost.
Optionally takes a file
name parameter, so calling C<$akf-E<gt>save("foo.txt")> will save the data
in the file "foo.txt" instead of the file the data was read from originally.

=back

=head1 LEGALESE

Copyright 2005-2009 by Mike Schilli, all rights reserved.
This program is free software, you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 AUTHOR

2005, Mike Schilli <m@perlmeister.com>
