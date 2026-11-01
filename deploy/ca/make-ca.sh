#!/usr/bin/env bash
# Create the course's internal root CA and a server certificate for the portal.
#
#   deploy/ca/make-ca.sh netsec.internal 10.10.20.5
#
# Output goes to deploy/ca/out/. Run once; rerun with --server-only to renew
# the server certificate without replacing the root students already trust.
#
# The root is NAME-CONSTRAINED: it can only issue certificates for *.internal
# names and private IP ranges. If its key ever leaked, it still could not be
# used to impersonate google.com to the students who trusted it.
set -euo pipefail

HOST="${1:?usage: make-ca.sh <hostname> <server-ip> [--server-only]}"
IP="${2:?usage: make-ca.sh <hostname> <server-ip> [--server-only]}"
MODE="${3:-}"
OUT="$(cd "$(dirname "$0")" && pwd)/out"
mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

if [[ "$MODE" != "--server-only" ]]; then
  if [[ -f ca.key ]]; then
    echo "ca.key already exists. Use --server-only to renew the server cert." >&2
    exit 1
  fi
  cat > ca.cnf <<CNF
[req]
distinguished_name = dn
prompt = no
x509_extensions = v3_ca
[dn]
CN = TE451 Network Security Lab Root CA
O = KNUST Dept. of Telecommunication Engineering
C = GH
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:.internal, permitted;DNS:internal, permitted;IP:10.0.0.0/255.0.0.0, permitted;IP:172.16.0.0/255.240.0.0, permitted;IP:192.168.0.0/255.255.0.0
CNF
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  chmod 600 ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 1825 -config ca.cnf -out ca.crt
  echo "Created root CA (5 years)."
fi

cat > server.cnf <<CNF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $HOST
[v3_server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$HOST, IP:$IP
authorityKeyIdentifier = keyid
subjectKeyIdentifier = hash
CNF
openssl ecparam -name prime256v1 -genkey -noout -out server.key
chmod 600 server.key
openssl req -new -key server.key -config server.cnf -out server.csr
# 397 days: inside Apple's and Chrome's maximum TLS certificate lifetime.
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 397 -sha256 -extfile server.cnf -extensions v3_server -out server.crt
cat server.crt ca.crt > fullchain.crt
rm -f server.csr
openssl verify -CAfile ca.crt server.crt

FP=$(openssl x509 -in ca.crt -noout -fingerprint -sha256 | cut -d= -f2)
echo
echo "Root CA SHA-256 fingerprint (put this in .env as ROOT_CA_FINGERPRINT):"
echo "  $FP"
echo
echo "Keep ca.key OFF the web server once you're done issuing; back it up offline."
