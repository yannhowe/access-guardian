#!/usr/bin/env bash
# Bundle each fix handler and zip it for Terraform.
# The zip path is dist/fixes/<name>.zip with index.js at the root.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# Zip stores the file's modification time, and Terraform hashes the whole zip.
# A clock time of "now" plans a Lambda update on every run even when the
# source did not change. These seconds are the ones already on the deployed
# zips. A real source change still changes the hash. A new fix uses the epoch
# so its first build is already stable.
# The zip also records the user id of the account that runs zip. Plan and
# apply both run as the GitHub Actions runner, so those two hashes match.
export TZ=UTC

zip_stamp() {
  case "$1" in
    close-open-port | contain-iam-user)
      printf '%s\n' '2026-10-28 19:04:48 UTC'
      ;;
    remove-bucket-public-access-block | restore-bucket-public-access-block)
      printf '%s\n' '2026-10-28 19:04:49 UTC'
      ;;
    daily)
      printf '%s\n' '2026-10-28 19:04:50 UTC'
      ;;
    *)
      printf '%s\n' '1980-01-01 00:00:00 UTC'
      ;;
  esac
}

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
  touch -d "$(zip_stamp "$name")" "${out}/index.js"
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
touch -d "$(zip_stamp daily)" "${out}/index.js"
rm -f "dist/reports/daily.zip"
(
  cd "$out"
  zip -q "../daily.zip" index.js
)
echo "built dist/reports/daily.zip"
