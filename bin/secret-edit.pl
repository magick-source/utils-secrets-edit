#!/usr/bin/perl -w

use strict;
use warnings;
use v5.18;

use FindBin qw($Bin);
use lib "$Bin/../lib/";
use Secrets qw(
    load_secrets
    store_secrets
  );

use Secrets::Vault qw(
    key_from_vault
    get_vault_key
    get_vault_path
    empty_vault
  );

use JSON qw(from_json);

my ($keyname, $filename) = @ARGV;
my $editing_vault = 0;
my $key;

if ($keyname eq '--my-vault' and !$filename) {
  $editing_vault = 1;
  $filename = get_vault_path();
  $key      = get_vault_key( $filename );
}

help() unless $filename and ( $key or $keyname );

unless ( $key or $ENV{ $keyname } ) {
  $key = key_from_vault( $keyname );
  unless ( $key ) {
    print STDERR "ERROR: Can't find key '$keyname'\n";
    exit 1;
  }
}

my $content = $editing_vault ? empty_vault() : '';
if ( -f $filename ) {
  $content = load_secrets( $key || $keyname, $filename );
}

my $new_content = edit_secrets( $filename, $content );
if ($new_content ne $content) {
  store_secrets( $key || $keyname, $filename, $new_content );
}

sub edit_secrets {
  my ($filename, $content) = @_;

  my ($dir,$fname);
  if ( $filename =~ m{/} ) {
    ($dir,$fname) = $filename =~ m{\A(.*/)([^/]+)\z};
  } else {
    ($dir,$fname) = ('',$filename);
  }
  if ( -d '/dev/shm/' ) {
    $dir      = '/dev/shm/';
    $fname = "$fname.$$";
  }

  my $edfname = "$dir.$fname.edsec";
  open my $fh, '>', $edfname or die "Error open edit file: $!";
  print $fh $content;
  close $fh;

  my $editor = $ENV{EDITOR} || '/usr/bin/vim';
  my @extra = ();
  if ($editor =~ /vim?/) {
    push @extra, '-n'; # disable swapfile
  }
  system($editor, @extra, $edfname);

  my $new_content;
  open $fh, '<', $edfname;
  {
    local $/;
    $new_content = <$fh>;
  }
  close $fh;
  unlink $edfname;

  return $new_content;
}

sub help {
  print <<EoH;
Usage:
  $0 <keyname> <filename>  || $0 --my-vault

  keyname - the name of the ENV variable where the key is stored

  filename - the name of the secrets file to edit
             the file will be created if it does not exit

  --my-vault - ask for a passphrase and open your personal vault
               this vault can be used to store key for other vaults

EoH
  exit 0;
}
