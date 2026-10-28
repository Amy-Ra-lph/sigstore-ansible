#!/bin/sh
# fulcio-start-pkcs11.sh — Startup script for Fulcio with PKCS#11 signer
#
# Key stays in HSM/NSS DB. Fulcio signs via PKCS#11 interface.
# Requires /etc/fulcio-config/pkcs11-config.json mounted into container.

exec /usr/local/bin/fulcio serve \
  --ca=pkcs11ca \
  --pkcs11-config-path=/etc/fulcio-config/pkcs11-config.json \
  --fileca-cert=/etc/fulcio-config/fulcio-ca.crt \
  --config-path=/etc/fulcio-config/config.json \
  --host=0.0.0.0 \
  --port=8080 \
  --ct-log-url= \
  --log_type=dev
