#!/bin/sh
set -eu
mkdir -p /certs /secrets
if [ ! -f /certs/server.pem ] || [ ! -f /certs/client.pem ] || [ ! -f /secrets/mongo-keyfile ]; then
  echo "[certgen] Creating lab CA, server/client certificates and replica-set keyfile"
  openssl genrsa -out /certs/ca.key 4096
  openssl req -x509 -new -nodes -key /certs/ca.key -sha256 -days 365 \
    -out /certs/ca.crt -subj "/CN=Lab12-MongoDB-CA"

  openssl genrsa -out /certs/server.key 2048
  openssl req -new -key /certs/server.key -out /certs/server.csr -subj "/CN=sec1"
  cat > /certs/server.ext <<'EOF'
subjectAltName=DNS:sec1,DNS:sec2,DNS:sec3,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth
keyUsage=digitalSignature,keyEncipherment
EOF
  openssl x509 -req -in /certs/server.csr -CA /certs/ca.crt -CAkey /certs/ca.key \
    -CAcreateserial -out /certs/server.crt -days 365 -sha256 -extfile /certs/server.ext
  cat /certs/server.key /certs/server.crt > /certs/server.pem
  chmod 600 /certs/server.key
  chmod 400 /certs/server.pem
  chown 999:999 /certs/server.pem

  openssl genrsa -out /certs/client.key 2048
  openssl req -new -key /certs/client.key -out /certs/client.csr -subj "/CN=lab12-pymongo-client"
  cat > /certs/client.ext <<'EOF'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature,keyEncipherment
EOF
  openssl x509 -req -in /certs/client.csr -CA /certs/ca.crt -CAkey /certs/ca.key \
    -CAcreateserial -out /certs/client.crt -days 365 -sha256 -extfile /certs/client.ext
  cat /certs/client.key /certs/client.crt > /certs/client.pem
  chmod 600 /certs/client.key /certs/client.pem

  openssl rand -base64 756 > /secrets/mongo-keyfile
  chmod 400 /secrets/mongo-keyfile
  chown 999:999 /secrets/mongo-keyfile
else
  echo "[certgen] Existing certificates and keyfile retained."
fi
echo "[certgen] Certificate files ready."
