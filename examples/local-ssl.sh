#!/bin/bash

# determine script directory and binary directory
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
BINDIR="$SCRIPTDIR/../src"

if [[ ! -x "$BINDIR/dw_node" || ! -x "$BINDIR/dw_client" ]]; then
    echo "Error: cannot find dw_node or dw_client in $BINDIR. Compile first or adjust path."
    exit 1
fi

WORKDIR="$(mktemp -d)"
echo "Using temp directory: $WORKDIR"

# enable xtrace
set -x

# 1) generate ephemeral CA, server, and client certs/keys
cd "$WORKDIR" || exit 1

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 -subj "/CN=DistWalkCA"

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=DistWalkServer" -addext "subjectAltName = IP:127.0.0.1"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1

openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=DistWalkClient"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 1

# 2) launch dw_node with SSL and custom ciphers
"$BINDIR/dw_node" \
    --bind-addr "ssl://localhost" \
    --ssl-cert "$WORKDIR/server.crt" \
    --ssl-key "$WORKDIR/server.key" \
    --ssl-ca "$WORKDIR/ca.crt" \
    --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384" \
    --nt 1 \
    &> "$WORKDIR/dw_node_ssl.log" &
NODEPID=$!
sleep 1

# 3) run dw_client with SSL and matching ciphers
"$BINDIR/dw_client" \
    --to "ssl://localhost" \
    --ssl-cert "$WORKDIR/client.crt" \
    --ssl-key "$WORKDIR/client.key" \
    --ssl-ca "$WORKDIR/ca.crt" \
    --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384" \
    -C 1000 \
    -n 5 \
    &> "$WORKDIR/dw_client_ssl.log"

# 4) kill dw_node
kill -SIGINT $NODEPID

# disable xtrace.
set +x

# output final instructions
echo "Client finished. Logs in:"
echo "  $WORKDIR/dw_node_ssl.log"
echo "  $WORKDIR/dw_client_ssl.log"
echo "Tail of client log:"
tail -n 10 "$WORKDIR/dw_client_ssl.log"
echo "======================================================"
echo "Temporary cert files and logs are in: $WORKDIR"
echo "When you're done, run the following command to remove"
echo "the temporary directory manually:"
echo "  rm -rf \"$WORKDIR\""
echo "======================================================"
