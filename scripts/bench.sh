#!/usr/bin/env bash
# Runs the decode benchmark sweep against in-process OpenZL C.
#
# Portable build by default: no target-cpu flags for ozlrip and plain -O3
# for OpenZL C. --native builds both sides with native CPU flags, using a
# separate OpenZL checkout and target dir so the two builds never mix.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/bench.sh [options]

  --native           build ozlrip and OpenZL C with native CPU flags
  --case NAME        run one case (OZLRIP_BENCH_CASE)
  --impl NAME        run one impl, e.g. ozlrip or openzl-c-ffi (OZLRIP_BENCH_IMPL)
  --target-ms N      measurement time per round (OZLRIP_BENCH_TARGET_MS)
  --features LIST    extra bench crate features, e.g. dev-format,no-checksum
  --no-plan-cache    disable the ozlrip plan cache (OZLRIP_BENCH_PLAN_CACHE=0)
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
native=0
features=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --native) native=1 ;;
    --case) export OZLRIP_BENCH_CASE="$2"; shift ;;
    --impl) export OZLRIP_BENCH_IMPL="$2"; shift ;;
    --target-ms) export OZLRIP_BENCH_TARGET_MS="$2"; shift ;;
    --features) features+=(--features "$2"); shift ;;
    --no-plan-cache) export OZLRIP_BENCH_PLAN_CACHE=0 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

upstream="$root/tmp/openzl-upstream"
if [[ ! -x "$upstream/zli" ]]; then
  echo "missing $upstream/zli: clone facebook/openzl there and run 'make zli'" >&2
  exit 1
fi
export OZLRIP_ZLI="${OZLRIP_ZLI:-$upstream/zli}"

target_base="$(
  cargo metadata --format-version 1 --no-deps --manifest-path "$root/bench/Cargo.toml" |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p'
)"

unset CARGO_ENCODED_RUSTFLAGS
if [[ $native -eq 1 ]]; then
  native_dir="$root/tmp/openzl-upstream-native"
  upstream_rev="$(git -C "$upstream" rev-parse HEAD)"
  if [[ "$(cat "$native_dir/.ozlrip-native-rev" 2>/dev/null)" != "$upstream_rev" ]]; then
    rm -rf "$native_dir"
    cp -a "$upstream" "$native_dir"
    rm -rf "$native_dir/cachedObjs" "$native_dir/libopenzl.a" "$native_dir/zli"
    make -C "$native_dir/deps/zstd/lib" clean >/dev/null
    make -C "$native_dir/deps/lz4/lib" clean >/dev/null
    echo "$upstream_rev" >"$native_dir/.ozlrip-native-rev"
  fi
  export RUSTFLAGS="-C target-cpu=native"
  export OZLRIP_OPENZL_DIR="$native_dir"
  export OZLRIP_OPENZL_MOREFLAGS="-march=native"
  export CARGO_TARGET_DIR="$target_base/bench-native"
else
  export RUSTFLAGS=""
  export OZLRIP_OPENZL_DIR="$upstream"
  export OZLRIP_OPENZL_MOREFLAGS=""
  export CARGO_TARGET_DIR="$target_base/bench-portable"
fi

exec cargo bench --manifest-path "$root/bench/Cargo.toml" --bench decode_profiles \
  ${features[@]+"${features[@]}"}
