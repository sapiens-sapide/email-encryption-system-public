email-encryption-system-public
==============================

C programs and Dovecot plugins for email encrypt/decrypt on the fly

These programs are part of Mailden system : a complete email provider system to securely encrypt/decrypt emails on the fly.
Programs rely on a postgreSQL db to work properly. There are part of a Postfix/Dovecot architecture.
Programs dependencies : libpq (postgreSQL libraries), libgcrypt (GNUPG libraries), crypt_blowfish (blowfish password hashing)

  **encrypt_One** : called by Dovecot plugin to encrypt email with user's public key
  
  **decrypt_One** : called by Dovecot plugin to decrypt email with user's private key
  
  **CreateUser** : launched by node webservices to create a new user in db, with public/private keys, passphrase, blowfish password hash…
  
  **mailden-filter** : hack from mail-filter dovecot plugin. Must be in dovecot/src/plugins and compiled with Dovecot.
