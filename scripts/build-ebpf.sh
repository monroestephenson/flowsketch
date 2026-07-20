#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/crates/flowsketch-ebpf/bpf/flowsketch_tc.bpf.c"
OUTPUT=${1:-"$ROOT/target/bpf/flowsketch_tc.bpf.o"}
CLANG=${CLANG:-clang}

case "$(uname -m)" in
  x86_64)
    target_arch=x86
    default_multiarch=x86_64-linux-gnu
    ;;
  aarch64 | arm64)
    target_arch=arm64
    default_multiarch=aarch64-linux-gnu
    ;;
  s390x)
    target_arch=s390
    default_multiarch=s390x-linux-gnu
    ;;
  ppc64le)
    target_arch=powerpc
    default_multiarch=powerpc64le-linux-gnu
    ;;
  riscv64)
    target_arch=riscv
    default_multiarch=riscv64-linux-gnu
    ;;
  *)
    echo "unsupported eBPF build architecture: $(uname -m)" >&2
    exit 2
    ;;
esac

if ! command -v "$CLANG" >/dev/null 2>&1; then
  echo "required eBPF compiler not found: $CLANG" >&2
  exit 127
fi
if ! test -f /usr/include/bpf/bpf_helpers.h; then
  echo "missing /usr/include/bpf/bpf_helpers.h (install libbpf-dev/libbpf-devel)" >&2
  exit 127
fi

mkdir -p "$(dirname -- "$OUTPUT")"
multiarch=$(cc -print-multiarch 2>/dev/null || true)
multiarch=${multiarch:-$default_multiarch}
if test -n "$multiarch" && test -d "/usr/include/$multiarch"; then
  "$CLANG" -O2 -g -target bpf -D"__TARGET_ARCH_$target_arch" \
    -I"/usr/include/$multiarch" -Wall -Werror \
    -c "$SOURCE" -o "$OUTPUT"
else
  "$CLANG" -O2 -g -target bpf -D"__TARGET_ARCH_$target_arch" \
    -Wall -Werror -c "$SOURCE" -o "$OUTPUT"
fi

echo "built eBPF tc object: $OUTPUT"
