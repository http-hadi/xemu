// Host capability probes for the "near-native" plan (see ../docs/NEAR_NATIVE_PLAN.md).
//
// Pure Win32 code: no WinRT in here, so the same file builds into the UWP app
// (main.cpp) and into a console harness (test_main.cpp) for local testing.
#pragma once
#include <stdio.h>
#include <string>
#include <vector>

namespace nn {

void SetLogFile(FILE *f);
const std::vector<std::string> &Summary();
void ClearSummary();

// Report-only line / report + on-screen summary line.
void Log(const char *fmt, ...);
void Sum(const char *fmt, ...);

// Safe probes (cannot kill the process): environment, API matrix, JIT,
// 4 KB placeholder views, fault round trips, VA limits, engine micro-benchmarks,
// FSGSBASE.
void RunSafeProbes();

// Crash-risk probes. State is persisted in <dir>\nn-probe-state.txt so that if
// the process is killed (which is itself a result) the next launch can say so.
void SetStateDir(const std::wstring &dir);
void ResolveCrashedTests(); // STARTED -> DIED, call once at launch
void ReportDangerousState();
void RunDangerous();

} // namespace nn
