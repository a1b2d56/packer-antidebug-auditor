#!/usr/bin/env bash
# Builds a trivial Windows PE (hello-world) and creates a UPX-packed copy,
# giving a reproducible packed/unpacked pair for testing the auditor
# without needing real malware samples.
#
# Requires: mingw-w64 (cross-compiler) and upx
#   Debian/Ubuntu: sudo apt-get install mingw-w64 upx-ucl
#   macOS (Homebrew): brew install mingw-w64 upx
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../samples"
mkdir -p "$OUT_DIR"

cat > /tmp/hello.c << 'EOF'
#include <windows.h>

int main(void) {
    Sleep(0);
    return 0;
}
EOF

echo "Compiling hello.exe with mingw-w64..."
x86_64-w64-mingw32-gcc /tmp/hello.c -o "$OUT_DIR/hello.exe"

echo "Packing with UPX..."
upx "$OUT_DIR/hello.exe" -o "$OUT_DIR/hello_packed.exe"

echo
echo "Done:"
echo "  $OUT_DIR/hello.exe         (unpacked baseline)"
echo "  $OUT_DIR/hello_packed.exe  (UPX-packed)"
echo
echo "Try:"
echo "  python cli.py $OUT_DIR/hello.exe"
echo "  python cli.py $OUT_DIR/hello_packed.exe"
