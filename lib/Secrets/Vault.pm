package Secrets::Vault;

use strict;
use warnings;
use v5.18;

use Term::ReadKey;
use Secrets qw(
    key_from_passphrase
    load_secrets
  );

use parent 'Exporter';
our @EXPORT_OK = qw(
  empty_vault
  get_vault_key
  get_vault_path
  key_from_vault
);

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

  return $vault->{ $keyname } || q{};
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


1;
