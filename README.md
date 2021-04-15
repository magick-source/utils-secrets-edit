# Secrets Editor

The Secrets Editor lets you edit (it's own flavour of) encrypted files.

## TL;DR

```bash

secret-key-gen 

secret-edit --my-vault

# Add key generated on top to the vault

secret-edit SOME_KEY_NAME config/file-with-secrets.json.enc 
# This will ask for the passphrase of the vault to get the key

# Alternative, set the key in the env (buuhhh, I know):

export SOME_KEY_NAME=.....
secret-edit SOME_KEY_NAME config/file-with-secrets.json.enc 


```

It can use a file encrypted by itself to store keys for other files. In
this case the file (it calls it my vault) is encrypted with a key
generated from a passphrase (and salted with an MD5 of the passphrase).

Files are encrypted using AES with 256 bit keys (if you use the provided
tool to generate the keys - it should work with 128 or 192 bits keys as
well, I guess) and a randomly generated IV/Nounce.

The nounce changes everytime the files is updated.

## How does it work?

The first time you edit one file, you start with an empty buffer, which
will be open in your editor of choice (the one defined by $ENV{EDITOR}.
or vim if you don't have $ENV{EDITOR} set.

If you are updating an existing file, the secrets editor loads and decrypts
the file - using a key from the env or from your vault file - writes the
decrypted content to a file named `.<originalname>.edsec` and opens the file
in your editor of choice.

When the editor exists, the secrets editor loads the content of the .edsec
file, deletes the file, check if the content changes, if so then generates
a new nounce, encrypts the new content and stores it in the file.

## What else does it do?

Absolutely nothing. This is it.

## Is this on CPAN? Will be be?

Maybe. I still need to add documentation and tests and stuff.

