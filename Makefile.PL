use ExtUtils::MakeMaker;

eval { require Net::DNS };
if ($@) {
  warn "*** The Net::DNS module is required for DNS checks\n";
}

WriteMakefile(
    'NAME'	   => 'Mail::Valid',
    'VERSION_FROM' => 'Valid.pm', 
    'PREREQ_PM'    => { 'Mail::Address' => 0 },
    'dist'         => { 'COMPRESS'=>'gzip -9f', 'SUFFIX' => 'gz',
                        'ZIP'=>'/usr/bin/zip', 'ZIPFLAGS'=>'-rl' }
);
