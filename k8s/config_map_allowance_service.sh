#!/bin/bash

# Set the namespace and ConfigMap name
NAMESPACE="world"
CONFIG_MAP_NAME="cm-allowance-service"

# get url, port, and client id from 1password
ALLOWANCE_URL=$(op read "op://world_site/apprentice_service_container_prod/url")
ALLOWANCE_PORT=$(op read "op://world_site/apprentice_service_container_prod/port")
ALLOWANCE_CLIENT_ID=$(op read "op://world_site/apprentice_service_container_prod/client_id")

# validate values are not empty
if [[ -z "$ALLOWANCE_URL" || -z "$ALLOWANCE_PORT" || -z "$ALLOWANCE_CLIENT_ID" ]]; then
  echo "Error: failed to get allowance config vars from 1Password."
  exit 1
fi

# generate cm yaml and apply
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CONFIG_MAP_NAME
  namespace: $NAMESPACE
data:
  allowance-url: "$ALLOWANCE_URL:$ALLOWANCE_PORT"
  allowance-port: ":$ALLOWANCE_PORT"
  allowance-client-id: "$ALLOWANCE_CLIENT_ID"
EOF
