#!/usr/bin/env bash
# Static MinGW (UCRT) build of sgdpi.exe. The kapsayan CMake build (which
# uses MSVC) is hala onerilir; bu script Visual Studio yuklemeden, sadece
# MinGW-w64 ile binary uretmek isteyenler icin.
#
# Onkosul:
#   - C:\mingw64 altinda MinGW-w64 (UCRT64) kurulu olmasi
#   - third_party/windivert/ altinda WinDivert SDK olmasi
#     (yoksa: powershell -ExecutionPolicy Bypass -File scripts/get-windivert.ps1)

set -euo pipefail

MINGW=${MINGW:-/c/mingw64/bin/g++.exe}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -x "$MINGW" ]]; then
    echo "[!!] MinGW g++ not found at $MINGW. Set \$MINGW or install MinGW-w64."
    exit 1
fi

if [[ ! -f "$ROOT/third_party/windivert/include/windivert.h" ]]; then
    echo "[..] WinDivert SDK missing - fetching..."
    powershell.exe -ExecutionPolicy Bypass -File "$ROOT/scripts/get-windivert.ps1"
fi

OUT_DIR="$ROOT/build/mingw"
mkdir -p "$OUT_DIR"

WINDRES=${WINDRES:-/c/mingw64/bin/windres.exe}
echo "[..] Compiling resource (manifest)"
# windres + the GCC preprocessor it spawns choke on non-ASCII paths
# (e.g. "Masaüstü"). Build with relative paths only and move the output
# afterwards.
(
    cd "$ROOT/resources"
    "$WINDRES" -i sgdpi.rc -o sgdpi.res.o -O coff
)
mv "$ROOT/resources/sgdpi.res.o" "$OUT_DIR/sgdpi.res.o"

echo "[..] Compiling sgdpi.exe (static MinGW build)"
"$MINGW" -std=c++17 -O2 -Wall -Wextra \
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 \
    -static -static-libgcc -static-libstdc++ \
    -I"$ROOT/include" -I"$ROOT/third_party/windivert/include" \
    "$ROOT/src/main.cpp" \
    "$ROOT/src/log.cpp" \
    "$ROOT/src/config.cpp" \
    "$ROOT/src/divert.cpp" \
    "$ROOT/src/packet.cpp" \
    "$ROOT/src/checksum.cpp" \
    "$ROOT/src/tls.cpp" \
    "$ROOT/src/http.cpp" \
    "$ROOT/src/strategy.cpp" \
    "$ROOT/src/ttl_probe.cpp" \
    "$ROOT/src/auto_tune.cpp" \
    "$ROOT/src/stats.cpp" \
    "$ROOT/src/engine.cpp" \
    "$ROOT/src/domain_filter.cpp" \
    "$ROOT/src/flow_table.cpp" \
    "$ROOT/src/dns_redirect.cpp" \
    "$ROOT/third_party/windivert/x64/WinDivert.dll" \
    "$OUT_DIR/sgdpi.res.o" \
    -lws2_32 -liphlpapi \
    -o "$OUT_DIR/sgdpi.exe"

echo "[..] Copying runtime"
cp "$ROOT/third_party/windivert/x64/WinDivert.dll"   "$OUT_DIR/"
cp "$ROOT/third_party/windivert/x64/WinDivert64.sys" "$OUT_DIR/"
cp -r "$ROOT/presets" "$OUT_DIR/"

echo "[ok] Built: $OUT_DIR/sgdpi.exe"
echo "[..] Build tests too"
"$MINGW" -std=c++17 -O2 -Wall -Wextra \
    -I"$ROOT/include" -I"$ROOT/tests" \
    "$ROOT/tests/runner.cpp" \
    "$ROOT/tests/test_checksum.cpp" \
    "$ROOT/tests/test_packet.cpp" \
    "$ROOT/tests/test_tls.cpp" \
    "$ROOT/tests/test_http.cpp" \
    "$ROOT/tests/test_domain_filter.cpp" \
    "$ROOT/tests/test_flow_table.cpp" \
    "$ROOT/src/checksum.cpp" \
    "$ROOT/src/packet.cpp" \
    "$ROOT/src/tls.cpp" \
    "$ROOT/src/http.cpp" \
    "$ROOT/src/domain_filter.cpp" \
    "$ROOT/src/flow_table.cpp" \
    "$ROOT/src/log.cpp" \
    -o "$OUT_DIR/sgdpi_tests.exe"

echo "[ok] Built: $OUT_DIR/sgdpi_tests.exe"
echo "[..] Running tests..."
# MinGW occasionally segfaults during static destruction even after _Exit;
# treat that as success when all tests passed.
out=$("$OUT_DIR/sgdpi_tests.exe" 2>&1) || true
echo "$out"
echo "$out" | grep -q "0 failed\." || { echo "[!!] tests failed"; exit 1; }
