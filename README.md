# Debian SSO Certificates plugin for Lemonldap::NG

## Debian certificates plugin

### To enable it:

 * add `customPlugins = Lemonldap::NG::Portal::Plugins::DebianSSOCerts` in
   /etc/lemonldap-ng.ini, section [portal]
 * add a menu entry that points to `https://<portal>/certs`

### Openssl installation

 * Set up a Openssl CA and create a openssl.sh that looks like:
```shell
#!/bin/sh
cd /openssl/working/directory
openssl "$@"
```
 * CA cert should be named `/openssl/working/directory/ca.crt`
 * CA private key should be named `/openssl/working/directory/ca.key`
 * Change permission to allow this directory to __www-data__ user only.

### Configuration:
 * to avoid mail filtering, change default "From" parameter in LLNG SMTP
   configuration
 * Override default parameters in `lemonldap-ng.ini` file, section `[portal]`.
   List:
   * **openssl**: path to `openssl.sh`. Default: `/var/lib/debian-sso/openssl.sh`
   * **gpgCertTokenTimeout**: timeout for GPG verification. Default: 600
   * **gpgDatabases**: GPG databases for high level certificates. Default:
     `/usr/share/keyrings/debian-nonupload.gpg /usr/share/keyrings/debian-keyring.gpg`
   * **opensslSignArgs**: openssl arguments to sign certs. Default:
     `x509 -req -CA ca.crt -CAkey ca.key -CAcreateserial -days`
   * **opensslHighSignArgs**: openssl arguments to high level certs. Default: same
     value than **opensslSignArgs**
   * **highCertAuthnLevel**, default: 5. Two usages:
     * authenticationLevel given after GPG verification
     * authenticationLevel required to get a high level certificate
   * **mailAttribute**: user attribute that contains user's mail. Default: `mail`

TODO:
 * improve CSS
 * improve all openssl commands (plugins directory)

## Debian registration plugin for non-DD)

TODO: finish it
