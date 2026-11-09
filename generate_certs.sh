#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[1/3] Створення Root CA..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ca.key -out ca.crt -days 365 \
    -subj "/CN=MyRootCA"

echo "[2/3] Створення сертифіката сервера..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=localhost"

openssl x509 -req -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")

echo "[3/3] Створення сертифіката клієнта..."
openssl req -newkey rsa:2048 -nodes \
    -keyout client.key -out client.csr \
    -subj "/CN=dispatcher-agent-01"

openssl x509 -req -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 \
    -extfile <(printf "extendedKeyUsage=clientAuth\n")

rm -f server.csr client.csr
chmod 600 ./*.key

echo "Готово. Сертифікати збережено в $CERT_DIR"
