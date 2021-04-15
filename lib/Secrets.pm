package Secrets;

use strict;
use warnings;
use v5.18;

our $VERSION = "0.01_01";

use parent 'Exporter';
our @EXPORT_OK = qw(
    load_secrets
    store_secrets
    encrypt
    decrypt
    key_gen
    key_from_passphrase
  );

use Digest::MD5 qw(md5_hex);
use MIME::Base64 qw(encode_base64 decode_base64);

use Crypt::Mode::CBC;
use Crypt::PRNG qw(random_bytes_hex);
use Crypt::KeyDerivation qw(pbkdf2);

my $sig = "SF&*";
my $fversion = 1;
my $vlen = 4;

sub load_secrets {
  my ($key, $filename) = @_;
  
  $key = get_key( $key );

  my $fcontent;
  open my $fh, '<', $filename;
  {
    local $/;
    $fcontent = <$fh>;
  }
  close $fh;

  $fcontent = join '', split /\n/, $fcontent;

  my $fsig = substr($fcontent, 0, 4);
  if ($fsig ne $sig) {
    die "'$filename' is not a valid secret vault";
  }
  my $fver = substr($fcontent, 4,4);
  if ($fver =~ m{\D}) {
    die "'$filename' doesn't see to have a valid version";
  } elsif ( $fver > $fversion ) {
    $fver += 0;
    die "'$filename' comes from the future (v$fver - ours: v$fversion)";
  }

  my $content = decrypt( $key, substr($fcontent, 9) );

  return $content;
}

sub store_secrets {
  my ($key, $filename, $content) = @_;

  $key = get_key( $key );

  my $cipher = encrypt( $key, $content );

  my $v = sprintf "%0${vlen}d", $fversion;
  my $out = "$sig$v;$cipher";

  $out = join "\n", ($out =~ m{(.{1,72})}g);

  open my $fh, '>', "$filename.tmp";
  print $fh $out;
  close $fh;

  rename "$filename.tmp", $filename;
}

sub decrypt {
  my ($key, $cipher) = @_;

  my $iv  = substr($cipher, 0, 32);
  my $chk = substr($cipher, 33, 32); #32 is ;
  $cipher = substr($cipher, 66);
  $cipher = decode_base64( $cipher );

  my $m = Crypt::Mode::CBC->new('AES');
  my $content = $m->decrypt( $cipher, $key, hex2bin($iv) );

  my $nchk = md5_hex( $content );

  if ($chk ne $nchk) {
    die "The decoded content doesn't seem right (checksum)";
  }

  return $content;
}

sub encrypt {
  my ($key, $content) = @_;

  my $chk = md5_hex( $content );
  my $m = Crypt::Mode::CBC->new('AES');
  my $iv = random_bytes_hex( 16 );
  my $cipher = $m->encrypt( $content, $key, hex2bin($iv));
  my $ecipher = encode_base64( $cipher, '' );

  return "$iv;$chk;$ecipher";
}

sub bin2hex {
  my ($binstr) = @_;

  my $hexstr = join '', map { sprintf "%02x", ord($_) } split //, $binstr;

  return $hexstr;
}

sub hex2bin {
  my ($hexstr) = @_;

  my $binstr = join '', map { chr(hex($_)) } $hexstr =~ m{(\w{2})}g;

  return $binstr;
}

sub get_key {
  my ($keyname) = @_;

  my $key = $ENV{ $keyname };
  if (!$key and $keyname =~ m{\A[0-9a-f]{64}\z}) {
    $key = $keyname;

  } elsif ( !$key ) {
    print STDERR "ERROR: key '$keyname' not found\n";
    exit 1;
  }

  $key = hex2bin( $key  );

  return $key;
}

sub key_from_passphrase {
  my ($pass, $salt) = @_;
  $salt ||= md5_hex( $pass );

  my $key = pbkdf2( $pass, $salt );

  $key = bin2hex( $key );

  return $key;
}

sub key_gen {
  my $key = random_bytes_hex(32);
 
  return $key;
}

1;
