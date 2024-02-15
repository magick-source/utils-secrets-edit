#!/usr/bin/perl -w

use strict;
use warnings;
use v5.18;

use FindBin qw($Bin);
use lib "$Bin/../lib/";
use Secrets qw(
    load_secrets
  );

my ($keyname, $filename) = @ARGV;

help() unless $filename and $keyname;

unless ( -f $filename ) {
  print STDERR "$filename: file not found";
  exit 1;
}

my $content = load_secrets( $keyname, $filename );

print $content,"\n";

sub help {
  print <<EoH;
Usage:
  $0 <keyname> <filename>

  keyname - the name of the ENV variable where the key is stored

  filename - the name of the secrets file to edit
             the file will be created if it does not exit

EoH
  exit 0;
}
