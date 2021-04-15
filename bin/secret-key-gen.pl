#!/usr/bin/perl -w

use strict;
use warnings;
use v5.18;

use FindBin qw($Bin);
use lib "$Bin/../lib/";
use Secrets qw(key_gen);

my $key = key_gen();
print "KEY: '$key'\n\n";
