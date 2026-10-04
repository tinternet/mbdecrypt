#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dev/out/plugins dev/out/metabase-data
cp metabase-sqlserver/target/sqlserver-decrypt.metabase-driver.jar dev/out/plugins/

container rm -f mbdecrypt-metabase >/dev/null 2>&1 || true

container run -d --name mbdecrypt-metabase -m 4G \
  -e MB_DB_FILE=/metabase-data/metabase.db -e MB_PLUGINS_DIR=/plugins -e JAVA_TIMEZONE=UTC \
  -e JAVA_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 \
  -v "$PWD/dev/out/plugins:/plugins" -v "$PWD/dev/out/metabase-data:/metabase-data" \
  "${METABASE_IMAGE:-metabase/metabase:v0.63.19.1}" >/dev/null

echo "Waiting for Metabase..."
until curl -fs http://mbdecrypt-metabase:3000/api/health >/dev/null 2>&1; do sleep 1; done
echo "Metabase is up"
exit
