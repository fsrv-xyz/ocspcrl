# OCSPCRL

OCSPCRL is a minimal implementation of both a OCSP and CRL server in Golang. It provides the following http endpoints:

- `/ocsp` - OCSP responder
- `/crl` - CRL responder

All what you need is to provide a CRL file, the root certificate and cert/key with extendedKeyUsage `OCSPSigning` to allow the OCSP server to sign the OCSP responses.
When using OCSP, the certificate is checked against the CRL for validity.

Synchronization of the CAs CRL is out of scope of this project. You can use any mechanism to update the CRL file. Just notify the ocspcrl server process via `SIGHUP` signal to reload the CRL file.
