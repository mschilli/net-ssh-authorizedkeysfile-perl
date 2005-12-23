######################################################################
# Makefile.PL for Net::SSH::AuthorizedKeysFile
# 2005, Mike Schilli <m@perlmeister.com>
######################################################################
use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'         => 'Net::SSH::AuthorizedKeysFile',
    'VERSION_FROM' => 'lib/Net/SSH/AuthorizedKeysFile.pm', # finds $VERSION
    'PREREQ_PM'    => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'lib/Net/SSH/AuthorizedKeysFile.pm',
       AUTHOR     => 'Mike Schilli <m@perlmeister.com>') : ()),
);
