#!/bin/sh
# trillian-signer-start.sh — Trillian log signer (SINGLETON)
#
# Must run on exactly ONE host (idm1). The signer sequences leaves
# into the Merkle tree. Running multiple signers causes race conditions.
#
# Environment variables:
#   MYSQL_URI — MariaDB connection string

MYSQL_URI="${MYSQL_URI:-trillian:trillian@tcp(localhost:3307)/trillian}"

exec /usr/local/bin/trillian_log_signer \
    --mysql_uri="$MYSQL_URI" \
    --http_endpoint=0.0.0.0:8091 \
    --force_master=true \
    --sequencer_interval=1s \
    --batch_size=500
