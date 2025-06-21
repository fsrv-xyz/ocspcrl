# OCSPCRL

OCSPCRL is a minimal implementation of both a OCSP and CRL server in Golang. It provides the following http endpoints:

| Endpoint   | Description                                              |
|------------|----------------------------------------------------------|
| `/ocsp`    | OCSP responder supporting both `GET` and `POST` requests |
| `/crl`     | CRL responder in DER format                              |
| `/crl.pem` | CRL responder in PEM format                              |
| `/ca`      | Issuer CA certificate in DER format                      |
| `/ca.pem`  | Issuer CA certificate in PEM format                      |

All what you need is to provide a CRL file, the root certificate and cert/key with extendedKeyUsage `OCSPSigning` to allow the OCSP server to sign the OCSP responses.
When using OCSP, the certificate is checked against the CRL for validity.

Synchronization of the CAs CRL is out of scope of this project. You can use any mechanism to update the CRL file. Just notify the ocspcrl server process via `SIGHUP` signal to reload the CRL file.
