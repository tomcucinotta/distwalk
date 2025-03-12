#!/bin/bash
#
# test_ssl_edge.sh
#
# This script tests various SSL/TLS edge cases:
#   1. A proper SSL configuration where both server and client enable SSL.
#   2. A mismatch where the server runs plain (no SSL) while the client expects SSL.
#   3. A mismatch where the server uses SSL but the client does not.
#   4. A certificate verification failure (client uses a wrong CA).
#
# Temporary certificates and keys are generated on the fly.
#

. common.sh

kill_all SIGKILL

TESTDIR=$(mktemp -d /tmp/test_ssl_edge.XXXX)
echo "Using temporary directory: $TESTDIR"

# ---------------------------------------------------------------------
# Generate certificates for tests.
# Create a CA, a server certificate (with subjectAltName for 127.0.0.1),
# and a client certificate. Also create a wrong CA for negative testing.
# ---------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout $TESTDIR/ca.key -out $TESTDIR/ca.crt -days 1 -subj "/CN=TestCA"

openssl genrsa -out $TESTDIR/server.key 2048
openssl req -new -key $TESTDIR/server.key -out $TESTDIR/server.csr -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
openssl x509 -req -in $TESTDIR/server.csr -CA $TESTDIR/ca.crt -CAkey $TESTDIR/ca.key -CAcreateserial -out $TESTDIR/server.crt -days 1

openssl genrsa -out $TESTDIR/client.key 2048
openssl req -new -key $TESTDIR/client.key -out $TESTDIR/client.csr -subj "/CN=TestClient"
openssl x509 -req -in $TESTDIR/client.csr -CA $TESTDIR/ca.crt -CAkey $TESTDIR/ca.key -CAcreateserial -out $TESTDIR/client.crt -days 1

# Create a wrong CA certificate for negative tests.
openssl req -x509 -newkey rsa:2048 -nodes -keyout $TESTDIR/wrong_ca.key -out $TESTDIR/wrong_ca.crt -days 1 -subj "/CN=WrongCA"

# ---------------------------------------------------------------------
# Test 1: Correct SSL configuration.
# Both server and client enable SSL using matching certificates and ciphers.
# ---------------------------------------------------------------------
echo "Test 1: Correct SSL configuration"
node_bg -b ssl:// --ssl-cert "$TESTDIR/server.crt" --ssl-key "$TESTDIR/server.key" --ssl-ca "$TESTDIR/ca.crt" --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384"
sleep 1
client --to ssl:// --ssl-cert "$TESTDIR/client.crt" --ssl-key "$TESTDIR/client.key" --ssl-ca "$TESTDIR/ca.crt" --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384" -C 1000 -n 3 > $TESTDIR/test1.log 2>&1
if grep -q "SSL handshake complete" $TESTDIR/test1.log; then
    echo "Test 1 SUCCESS: SSL handshake succeeded."
else
    echo "Test 1 ERROR: Expected successful SSL handshake."
    exit 1
fi
kill_all SIGINT
sleep 1

# ---------------------------------------------------------------------
# Test 2: Mismatch: Server plain, Client expects SSL.
# The client should fail its SSL handshake.
# ---------------------------------------------------------------------
echo "Test 2: Server plain, client SSL"
node_bg   # start server without --ssl
sleep 1
client --to ssl:// --ssl-cert "$TESTDIR/client.crt" --ssl-key "$TESTDIR/client.key" --ssl-ca "$TESTDIR/ca.crt" --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384" -C 1000 -n 3 > $TESTDIR/test2.log 2>&1
if greq -q "SSL handshake failed" $TESTDIR/test2.log; then
    echo "Test 2 ERROR: Expected failure due to SSL mismatch (server plain, client SSL)."
    exit 1
else
    echo "Test 2 SUCCESS: SSL handshake failed as expected."
fi
kill_all SIGINT
sleep 1

# ---------------------------------------------------------------------
# Test 3: Mismatch: Server uses SSL, Client is plain.
# The client will not perform SSL, so the connection should fail.
# ---------------------------------------------------------------------
echo "Test 3: Server SSL, client plain"
node_bg -b ssl:// --ssl-cert "$TESTDIR/server.crt" --ssl-key "$TESTDIR/server.key" --ssl-ca "$TESTDIR/ca.crt" --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384"
sleep 1
client -C 1000 -n 3 > $TESTDIR/test3.log 2>&1
if grep -q "SSL handshake failed" $TESTDIR/test3.log; then
    echo "Test 3 ERROR: Expected failure due to SSL mismatch (server SSL, client plain)."
    exit 1
else
    echo "Test 3 SUCCESS: Connection failed as expected."
fi
kill_all SIGINT
sleep 1

# ---------------------------------------------------------------------
# Test 4: Certificate verification failure.
# Client uses an incorrect CA so that verification fails.
# ---------------------------------------------------------------------
echo "Test 4: Wrong CA certificate on client"
node_bg -b ssl:// --ssl-cert "$TESTDIR/server.crt" --ssl-key "$TESTDIR/server.key" --ssl-ca "$TESTDIR/ca.crt" --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384"
sleep 1
client --to ssl:// --ssl-cert "$TESTDIR/client.crt" --ssl-key "$TESTDIR/client.key" --ssl-ca "$TESTDIR/wrong_ca.crt" --ssl-ciphers "ECDHE-RSA-AES256-GCM-SHA384" -C 1000 -n 3 > $TESTDIR/test4.log 2>&1
if grep -q "SSL handshake failed" $TESTDIR/test4.log; then
    echo "Test 4 ERROR: Expected failure due to certificate verification error."
    exit 1
else
    echo "Test 4 SUCCESS: SSL handshake failed as expected due to wrong CA."
fi
kill_all SIGINT
sleep 1

echo "All SSL tests finished successfully."
rm -rf "$TESTDIR"
