#!/bin/bash

set -e

echo "Waiting for ClickHouse to be ready..."
until docker exec clickhouse-server clickhouse-client --query "SELECT 1" > /dev/null 2>&1; do
    echo "ClickHouse is unavailable - sleeping"
    sleep 2
done

echo "ClickHouse is ready!"

echo "Creating database and tables..."
docker exec clickhouse-server clickhouse-client --multiquery < clickhouse_schema.sql

echo "ClickHouse initialization complete!"
echo "You can connect to ClickHouse at http://localhost:8123"
echo "Database: garuda"

# Verify tables were created
echo "Verifying tables..."
docker exec clickhouse-server clickhouse-client --query "SHOW TABLES FROM garuda"

echo "Sample data verification:"
docker exec clickhouse-server clickhouse-client --query "SELECT count() FROM garuda.decisions"