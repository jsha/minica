#!/bin/bash

set -e
echo "world" > hello

minica localhost

set +e
# FIXME: jsha/minica puts the keypair in a directory, copy those out for compatibility
# so the same tests work against either version.
cp localhost/cert.pem localhost.crt
cp localhost/key.pem localhost.key
cp minica.pem cacert.crt
set -e

openssl s_server -cert localhost.crt -key localhost.key -accept 8080 -WWW &
set +e

curl https://localhost:8080/hello
if (( $? != 60 )); then
	exit "Expected request to server with untrusted CA to fail."
fi

set -e
cp cacert.crt /usr/share/ca-certificates/
echo "cacert.crt" >> /etc/ca-certificates.conf
update-ca-certificates	
set +e

curl https://localhost:8080/hello
if (( $? != 0 )); then
	exit "Expected request to server with trusted CA to succeed."
fi

# FIXME: -ca-key-size and -key-size are paultag/minica-only right now, but could be ported.
# set -e
# minica -ca-key-size 4096 -key-size 4096 127.0.0.1
# openssl s_server -cert 127.0.0.1.crt -key 127.0.0.1.key -accept 8081 -WWW &
# set +e

# curl https://127.0.0.1:8081/hello
# if (( $? != 0 )); then
# 	exit "Expected request to server with trusted CA to succeed."
# fi