#!/bin/sh
set -e
host="$1"
shift
cmd="$@"
until pg_isready -h "$host" -p 5432 -U "$POSTGRES_USER"; do
  >&2 echo "Postgres ist noch nicht verfügbar - warte..."
  sleep 2
done
>&2 echo "Postgres ist verfügbar - starte Befehl"
exec $cmd
