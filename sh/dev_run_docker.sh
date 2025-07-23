#!/bin/bash

docker build -t apprentice .

docker run -d --rm -p $(op read "op://world_site/apprentice_service_container_dev/port"):$(op read "op://world_site/apprentice_service_container_dev/port") \
    -e APPRENTICE_SERVICE_CLIENT_ID=$(op read "op://world_site/apprentice_service_container_dev/client_id") \
    -e APPRENTICE_SERVICE_PORT=":$(op read "op://world_site/apprentice_service_container_dev/port")" \
    -e APPRENTICE_CA_CERT="$(op document get "service_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_SERVER_CERT="$(op document get "apprentice_service_server_dev_cert" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_SERVER_KEY="$(op document get "apprentice_service_server_dev_key" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_CLIENT_CERT="$(op document get "apprentice_service_client_dev_cert" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_CLIENT_KEY="$(op document get "apprentice_service_client_dev_key" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_S2S_AUTH_URL="$(op read "op://world_site/ran_service_container_dev/url"):$(op read "op://world_site/ran_service_container_dev/port")" \
    -e APPRENTICE_S2S_AUTH_CLIENT_ID="$(op read "op://world_site/apprentice_service_container_dev/client_id")" \
    -e APPRENTICE_S2S_AUTH_CLIENT_SECRET="$(op read "op://world_site/apprentice_service_container_dev/password")" \
    -e APPRENTICE_DB_CA_CERT="$(op document get "db_ca_dev_cert" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_DB_CLIENT_CERT="$(op document get "apprentice_db_client_dev_cert" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_DB_CLIENT_KEY="$(op document get "apprentice_db_client_dev_key" --vault world_site | base64 -w 0)" \
    -e APPRENTICE_DATABASE_URL="$(op read "op://world_site/apprentice_db_dev/server"):$(op read "op://world_site/apprentice_db_dev/port")" \
    -e APPRENTICE_DATABASE_NAME="$(op read "op://world_site/apprentice_db_dev/database")" \
    -e APPRENTICE_DATABASE_USERNAME="$(op read "op://world_site/apprentice_db_dev/username")" \
    -e APPRENTICE_DATABASE_PASSWORD="$(op read "op://world_site/apprentice_db_dev/password")" \
    -e APPRENTICE_DATABASE_HMAC_INDEX_SECRET="$(op read "op://world_site/apprentice_hmac_index_secret_dev/secret")" \
    -e APPRENTICE_FIELD_LEVEL_AES_GCM_SECRET="$(op read "op://world_site/apprentice_aes_gcm_secret_dev/secret")" \
    -e APPRENTICE_USER_AUTH_URL=$(op read "op://world_site/shaw_service_container_dev/url"):$(op read "op://world_site/shaw_service_container_dev/port") \
    -e APPRENTICE_S2S_JWT_VERIFYING_KEY="$(op read "op://world_site/ran_jwt_key_pair_dev/verifying_key")" \
    -e APPRENTICE_USER_JWT_VERIFYING_KEY="$(op read "op://world_site/shaw_jwt_key_pair_dev/verifying_key")" \
    apprentice:latest
