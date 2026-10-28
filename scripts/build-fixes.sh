#!/usr/bin/env bash
# Bundle each fix handler and zip it for Terraform.
# The zip path is dist/fixes/<name>.zip with index.js at the root.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

found=0
for handler in src/fixes/*/handler.ts; do
  if [[ ! -f "$handler" ]]; then
    continue
  fi
  found=1
  name="$(basename "$(dirname "$handler")")"
  out="dist/fixes/${name}"
  mkdir -p "$out"
  npx esbuild "$handler" \
    --bundle \
    --platform=node \
    --target=node20 \
    --format=cjs \
    --outfile="${out}/index.js"
  rm -f "dist/fixes/${name}.zip"
  (
    cd "$out"
    zip -q "../${name}.zip" index.js
  )
  echo "built dist/fixes/${name}.zip"
done

if [[ "$found" -ne 1 ]]; then
  echo "no fix handlers under src/fixes" >&2
  exit 1
fi

# The daily report is read-only and is not a fix. The plan job already runs
# this script, so the report zip is built here too. index.js at the root,
# handler index.handler, same as the fix zips.
report_handler="src/reports/daily/handler.ts"
if [[ ! -f "$report_handler" ]]; then
  echo "missing ${report_handler}" >&2
  exit 1
fi
out="dist/reports/daily"
mkdir -p "$out"
npx esbuild "$report_handler" \
  --bundle \
  --platform=node \
  --target=node20 \
  --format=cjs \
  --outfile="${out}/index.js"
rm -f "dist/reports/daily.zip"
(
  cd "$out"
  zip -q "../daily.zip" index.js
)
echo "built dist/reports/daily.zip"
