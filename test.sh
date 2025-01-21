openssl ocsp -CAfile ../../ca/ca.crt -url http://127.0.0.1:8080 -issuer ../../ca/ca.crt -resp_text -cert ../../test.crt
