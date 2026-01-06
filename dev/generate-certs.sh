#!/bin/bash
set -e

cd "$(dirname "$0")"

mkdir -p certs

mkcert -install

cp "$(mkcert -CAROOT)/rootCA.pem" certs/

mkcert -cert-file certs/mailpit.pem -key-file certs/mailpit-key.pem \
    "mailpit" \
    "*.mailpit" \
    "localhost" \
    "172.30.0.3" \
    "smtp_test"

mkcert -cert-file certs/server.pem -key-file certs/server-key.pem \
    "localhost" \
    "127.0.0.1" \
    "::1" \
    "smtp" \
    "0.0.0.0"

openssl genrsa -out certs/dkim-private.pem 2048

chmod 644 certs/*.pem
chmod 600 certs/*-key.pem certs/dkim-private.pem

echo "Certificates generated in dev/certs/"
