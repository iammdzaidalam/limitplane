#!/usr/bin/env bash
# Hammer two replicas via nginx. A shared limit admits ~LIMIT; per-replica limits would admit ~2x.
set -euo pipefail
URL=${URL:-http://localhost:8080/}
KEY=${KEY:-}
LIMIT=${LIMIT:-10}
N=${N:-$((LIMIT * 2))}
SLACK=${SLACK:-3} # tokens refilled while the loop runs

hdr=()
[ -n "$KEY" ] && hdr=(-H "X-Api-Key: $KEY")

out=$(for _ in $(seq "$N"); do
  curl -s -o /dev/null -D - ${hdr[@]+"${hdr[@]}"} "$URL" | awk 'NR==1{c=$2} tolower($1)=="x-served-by:"{s=$2} END{print c, s}'
done)

echo "$out" | sort | uniq -c
ok=$(echo "$out" | awk '$1==200' | wc -l | tr -d ' ')
echo "200s: $ok  expected: $LIMIT (+$SLACK slack)  requests: $N"
[ "$ok" -ge "$LIMIT" ] && [ "$ok" -le $((LIMIT + SLACK)) ] && echo "PASS: limit shared across replicas" || { echo "FAIL"; exit 1; }
