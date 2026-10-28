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
