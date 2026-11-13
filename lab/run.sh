#!/bin/sh
# Fixed POSIX entry point. It never installs host packages or modifies host services.
set -eu

usage() {
  printf '%s\n' 'Usage: sh lab/run.sh [--output /absolute/new-report.json] [--no-prepare]'
  printf '%s\n' '       sh lab/run.sh --plan'
  printf '%s\n' 'Default: run all local checks and prepare only the pinned lab images.'
}

mode=run
prepare=yes
output=
seen_plan=no
seen_output=no
seen_prepare=no
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --plan)
      [ "$seen_plan" = no ] || { usage >&2; exit 1; }
      mode=plan; seen_plan=yes; shift ;;
    --output)
      [ "$seen_output" = no ] && [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 1; }
      output=$2; seen_output=yes; shift 2 ;;
    --no-prepare)
      [ "$seen_prepare" = no ] || { usage >&2; exit 1; }
      prepare=no; seen_prepare=yes; shift ;;
    *) usage >&2; exit 1 ;;
  esac
done
if [ "$mode" = plan ] && { [ "$seen_output" = yes ] || [ "$seen_prepare" = yes ]; }; then
  usage >&2; exit 1
fi
command -v node >/dev/null 2>&1 || { printf '%s\n' 'Node.js 22 or later is required.' >&2; exit 2; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$repo_dir"
if [ "$mode" = plan ]; then
  exec node scripts/verify.mjs --plan
fi
if [ -n "$output" ]; then
  case "$output" in /*) ;; *) printf '%s\n' 'Output must be an absolute POSIX path.' >&2; exit 1 ;; esac
else
  output_dir=$(mktemp -d "${TMPDIR:-/tmp}/security-lab-report-XXXXXXXX")
  output=$output_dir/report.json
  printf 'Report directory retained at: %s\n' "$output_dir" >&2
fi
if [ "$prepare" = yes ]; then
  exec node scripts/verify.mjs --all --prepare --output "$output"
fi
exec node scripts/verify.mjs --all --output "$output"
