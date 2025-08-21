#!/bin/sh
set -euo pipefail
CLICKHOUSE_HOST=${CLICKHOUSE_HOST:-clickhouse}
CLICKHOUSE_PORT=${CLICKHOUSE_PORT:-9000}
CLICKHOUSE_USER=${CLICKHOUSE_USER:-default}
CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD:-}

# Wait a bit for clickhouse to be ready
for i in $(seq 1 30); do
  if clickhouse-client --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --user "$CLICKHOUSE_USER" ${CLICKHOUSE_PASSWORD:+--password "$CLICKHOUSE_PASSWORD"} --query "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  echo "Waiting for ClickHouse... ($i)"
  sleep 1
done

clickhouse-client --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" --user "$CLICKHOUSE_USER" ${CLICKHOUSE_PASSWORD:+--password "$CLICKHOUSE_PASSWORD"} --multiquery < /scripts/clickhouse_schema.sql

echo "ClickHouse schema initialized."