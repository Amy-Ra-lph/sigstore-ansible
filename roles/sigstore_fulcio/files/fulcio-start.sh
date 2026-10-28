#!/bin/sh
exec /usr/local/bin/fulcio serve \
  --ca=fileca \
  --fileca-cert=/etc/fulcio-config/fulcio-intermediate.crt \
  --fileca-key=/etc/fulcio-config/fulcio-key.pem \
  --fileca-key-passwd="$FULCIO_FILECA_KEY_PASSWD" \
  --config-path=/etc/fulcio-config/config.json \
  --host=0.0.0.0 \
  --port=8080 \
  --ct-log-url= \
  --log_type=dev
