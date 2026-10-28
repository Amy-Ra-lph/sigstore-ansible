#!/bin/sh
# trillian-logserver-start.sh — Trillian log server (stateless)
#
# Runs on every host that has a Rekor frontend.
# Connects to MariaDB for all state.
#
# Environment variables:
#   MYSQL_URI — MariaDB connection string

MYSQL_URI="${MYSQL_URI:-trillian:trillian@tcp(localhost:3307)/trillian}"

exec /usr/local/bin/trillian_log_server \
    --mysql_uri="$MYSQL_URI" \
    --rpc_endpoint=0.0.0.0:8090 \
    --http_endpoint=0.0.0.0:8092
