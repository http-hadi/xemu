#!/usr/bin/env bash
# Builds probes.cpp as a console program with MinGW and runs it under Wine.
# This is how the probe logic was exercised before it went into the UWP package.
# It cannot tell you anything about the console (Wine's placeholder and exception
# behaviour differ), only that the probe code itself works.
#
#   sudo apt-get install g++-mingw-w64-x86-64 wine64
#   tools/run-local-harness.sh            # safe tests
#   tools/run-local-harness.sh danger     # crash-risk tests (A2 is expected to kill the process)
set -euo pipefail
cd "$(dirname "$0")/../UWP-NearNativeProbe"
x86_64-w64-mingw32-g++ -O2 -std=c++17 -Wall -Wextra -mxsave -static -o /tmp/nn_test.exe test_main.cpp probes.cpp
export WINEPREFIX="${WINEPREFIX:-/tmp/wineprefix}" WINEDEBUG=-all DISPLAY= NN_SKIP_VA=1
WINE="$(command -v wine64 || echo /usr/lib/wine/wine64)"
cd /tmp
case "${1:-safe}" in
  danger) rm -f nn-probe-state.txt; "$WINE" nn_test.exe danger-only || true ; "$WINE" nn_test.exe danger-only ;;
  *)      "$WINE" nn_test.exe ;;
esac
