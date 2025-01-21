#!/usr/bin/env bash
set -xeou pipefail

# go run main.go --responder.certificate-path ../tinypki/ca/ca.crt --responder.key-path ../tinypki/ca/ca.key --ca-crt-path ../tinypki/ca/ca.crt --source.file.path ../tinypki/root.crl

ca_dir="$(dirname $(readlink -f $0))/../tinypki"
ocsp_url="$(openssl x509 -noout -ocsp_uri -in $ca_dir/dev-server.crt)"
openssl ocsp \
  -CAfile $ca_dir/ca/ca.crt \
  -url "$ocsp_url" \
  -issuer $ca_dir/ca/ca.crt \
  -resp_text \
  -cert $ca_dir/dev-server.crt

openssl verify -crl_check -crl_download -CAfile $ca_dir/ca/ca.crt $ca_dir/dev-server.crt