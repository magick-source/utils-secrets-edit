#!/usr/bin/perl -w 

use strict;
use warnings;
use v5.18;

use FindBin qw($Bin);
use lib "$Bin/../lib/";
use Secrets qw(
    load_secrets
    store_secrets
    key_from_passphrase
  );

use Term::ReadKey;
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
  my $edfname = "$dir.$fname.edsec";
  open my $fh, '>', $edfname or die "Error open edit file: $!";
  print $fh $content;
  close $fh;

  my $editor = $ENV{EDITOR} || '/usr/bin/vim';
  system($editor, $edfname);

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

sub key_from_vault {
  my ($keyname) = @_;

  my $vault_path = get_vault_path();
  my $vault_key  = get_vault_key( $vault_path );
  
  return unless -f $vault_path;

  my $_vault = load_secrets( $vault_key, $vault_path );
  return unless $_vault;

  my $vault;
  eval {
    $vault = from_json( $_vault, { utf8 => 1, relaxed => 1 });
  } or do {
    my $err = $@;
    print STDERR "Error loading vault:\n\t$err\n";
    exit 1;
  };

  return $vault->{ $keyname } || '';
}

sub get_vault_key {
  my ($fname) = @_;
  Term::ReadKey::ReadMode('noecho');

  print "Type the passphrase for '$fname': ";
  my $passphrase = Term::ReadKey::ReadLine(0);

  Term::ReadKey::ReadMode('restore');
  print "\n";

  my $key = key_from_passphrase( $passphrase );

  return $key;
}

sub get_vault_path {
  my $path = $ENV{SRV_VAULT_PATH} || "$ENV{HOME}/.config/.srv.vault";

  return $path;
}

sub empty_vault {
  return <<EoV;
{
# "KEY_NAME": "HEX_KEY_STRING",
}
EoV
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
