# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..10\n"; }
END {print "not ok 1\n" unless $loaded;}
use Mail::Valid;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$test = 2;
my $v = new Mail::Valid;

sub not_ok { print "not ok $test\n"; $test++ }
sub ok { print "ok $test\n"; $test++ }

$v->address('Alfred Neuman <Neuman@BBN-TENEXA>') ? not_ok : ok;

$v->address( -address => 'Alfred Neuman <Neuman@BBN-TENEXA>',
             -fqdn    => 0) ? ok : not_ok;

my $a = $v->address( -address => 'first last@aol.com',
                     -fudge   => 1);
$a->address eq 'firstlast@aol.com' ? ok : not_ok;

$v->address( -address => 'first last@aol.com',
             -fudge   => 0) ? not_ok : ok;
$v->details eq 'rfc822' ? ok : not_ok;

$a = $v->address('foo @ foo.com');
$a->address eq 'foo@foo.com' ? ok : not_ok;
 
$a = $v->address("fred&barney\@stonehenge(yup, the rock place).(that's dot)com");
$a->address eq 'fred&barney@stonehenge.com' ? ok : not_ok;   

if ($v->dns_loaded) {
  $v->address( -address => 'blort@aol.com',
               -mxcheck => 1) ? ok : not_ok;
  $v->address( -address => 'blort@notarealdomainfoo.com',
               -mxcheck => 1) ? not_ok : ok;   
} else {
  warn "\n\n*** Skipping DNS tests\n\n";
  ok;
  ok;
}

