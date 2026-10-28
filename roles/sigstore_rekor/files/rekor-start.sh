#!/bin/sh
# rekor-start.sh — Startup script for Rekor transparency log container
#
# Creates the Trillian Merkle tree on first run (persists tree_id to file),
# then starts the Rekor server. If REKOR_TREE_ID is set in the environment,
# uses that directly (for multi-host deployments where the tree was already
# created on another host).
#
# Environment variables:
#   TRILLIAN_LOG_SERVER_ADDR — Trillian gRPC address (default: localhost:8090)
#   REKOR_TREE_ID            — Pre-existing tree ID (skip createtree if set)
#   REKOR_TREE_ID_FILE       — Path to persist tree ID (default: /var/lib/rekor/tree_id)

# Parse TRILLIAN_LOG_SERVER_ADDR (host:port format) into separate vars
TRILLIAN_LOG_SERVER_ADDR="${TRILLIAN_LOG_SERVER_ADDR:-localhost:8090}"
TRILLIAN_HOST="${TRILLIAN_LOG_SERVER_ADDR%:*}"
TRILLIAN_PORT="${TRILLIAN_LOG_SERVER_ADDR#*:}"
TREE_ID_FILE="${REKOR_TREE_ID_FILE:-/var/lib/rekor/tree_id}"

# Wait for Trillian to be ready (Rekor will retry internally, but give it a head start)
echo "Rekor: waiting for Trillian at $TRILLIAN_HOST:$TRILLIAN_PORT..."
sleep 5

# Determine tree ID: env var > persisted file > create new
if [ -n "${REKOR_TREE_ID:-}" ] && [ "$REKOR_TREE_ID" != "@@REKOR_TREE_ID@@" ]; then
    TREE_ID="$REKOR_TREE_ID"
    echo "Rekor: using tree ID from environment: $TREE_ID"
    echo "$TREE_ID" > "$TREE_ID_FILE"
elif [ -f "$TREE_ID_FILE" ] && [ -s "$TREE_ID_FILE" ]; then
    TREE_ID=$(cat "$TREE_ID_FILE")
    echo "Rekor: using persisted tree ID: $TREE_ID"
else
    echo "Rekor: creating new Merkle tree..."
    TREE_OUTPUT=$(/usr/local/bin/createtree \
        --admin_server="${TRILLIAN_HOST}:${TRILLIAN_PORT}" \
        --tree_type=LOG \
        --description="IPA Sigstore Rekor Log" 2>&1)

    TREE_ID=$(echo "$TREE_OUTPUT" | grep -oE '^[0-9]+$' | head -1)

    if [ -z "$TREE_ID" ]; then
        echo "ERROR: Failed to create Merkle tree"
        echo "$TREE_OUTPUT"
        exit 1
    fi

    echo "$TREE_ID" > "$TREE_ID_FILE"
    echo "Rekor: created tree ID: $TREE_ID"
fi

echo "Rekor: starting server (tree=$TREE_ID)..."
exec /usr/local/bin/rekor-server serve \
    --rekor_server.address=0.0.0.0 \
    --port=3000 \
    --trillian_log_server.address="$TRILLIAN_HOST" \
    --trillian_log_server.port="$TRILLIAN_PORT" \
    --trillian_log_server.tlog_id="$TREE_ID" \
    --search_index.storage_provider=mysql \
    --search_index.mysql.dsn="${SEARCH_INDEX_DSN:-trillian:trillian@tcp(localhost:3307)/trillian}" \
    --rekor_server.signer=/etc/rekor/rekor-signing-key.pem \
    --enable_stable_checkpoint=false \
    --log_type=dev
