#!/bin/bash
openssl req -x509 -out localhost.crt -keyout localhost.key \
    -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=localhost' -extensions EXT -config <(
        printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost,DNS:*.127.0.0.1.nip.io\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth"
    )
