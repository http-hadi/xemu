// Host capability probes for the "near-native" plan.
// Every number printed here replaces an assumption in the design doc.
//
// Rules this file follows:
//  * every OS entry point that might be missing/blocked in the UWP sandbox is
//    resolved with GetProcAddress, so "missing" is a *result*, not a crash;
//  * the report is flushed line by line, so a hang or crash still leaves
//    partial results;
//  * anything that can kill the process lives in RunDangerous() and is
//    bracketed by STARTED/finished markers in a state file.

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <utility>
#include "probes.h"

#if defined(_MSC_VER)
extern "C" WINBASEAPI BOOL WINAPI GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE *phModule);
#define NN_NOINLINE __declspec(noinline)
#define NN_UNLIKELY(x) (x)
#else
#define NN_NOINLINE __attribute__((noinline))
#define NN_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#ifndef MEM_REPLACE_PLACEHOLDER
#define MEM_REPLACE_PLACEHOLDER 0x00004000
#endif
#ifndef MEM_RESERVE_PLACEHOLDER
#define MEM_RESERVE_PLACEHOLDER 0x00040000
#endif
#ifndef MEM_PRESERVE_PLACEHOLDER
#define MEM_PRESERVE_PLACEHOLDER 0x00000002
#endif
#ifndef MEM_COALESCE_PLACEHOLDERS
#define MEM_COALESCE_PLACEHOLDERS 0x00000001
#endif
#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE 0x0020
#endif

namespace nn {

// ------------------------------------------------------------------ logging --

static FILE *g_log = nullptr;
static std::vector<std::string> g_summary;

void SetLogFile(FILE *f) { g_log = f; }
const std::vector<std::string> &Summary() { return g_summary; }
void ClearSummary() { g_summary.clear(); }

static void emit(const std::string &s)
{
    if (g_log) {
        fputs(s.c_str(), g_log);
        fputc('\n', g_log);
        fflush(g_log);
    }
}

static std::string vfmt(const char *fmt, va_list ap)
{
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    buf[sizeof(buf) - 1] = 0;
    return std::string(buf);
}

void Log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::string s = vfmt(fmt, ap);
    va_end(ap);
    emit(s);
}

void Sum(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::string s = vfmt(fmt, ap);
    va_end(ap);
    g_summary.push_back(s);
    emit(s);
}

#define L(...) Log(__VA_ARGS__)
#define S(...) Sum(__VA_ARGS__)

// ------------------------------------------------------------------- timing --

static double qpc_freq()
{
    static double f = 0;
    if (f == 0) {
        LARGE_INTEGER x;
        QueryPerformanceFrequency(&x);
        f = (double)x.QuadPart;
    }
    return f;
}

static uint64_t qpc()
{
    LARGE_INTEGER x;
    QueryPerformanceCounter(&x);
    return (uint64_t)x.QuadPart;
}

static double ns_since(uint64_t t0) { return (double)(qpc() - t0) * 1e9 / qpc_freq(); }

// ------------------------------------------------------ dynamic API lookup --

typedef LPVOID (WINAPI *PFN_VirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void *, ULONG);
typedef LPVOID (WINAPI *PFN_VirtualAllocFromApp)(PVOID, SIZE_T, ULONG, ULONG);
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_VirtualProtectFromApp)(PVOID, SIZE_T, ULONG, PULONG);
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *PFN_CreateFileMappingFromApp)(HANDLE, PSECURITY_ATTRIBUTES, ULONG, ULONG64, PCWSTR);
typedef PVOID (WINAPI *PFN_MapViewOfFileFromApp)(HANDLE, ULONG, ULONG64, SIZE_T);
typedef HANDLE (WINAPI *PFN_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI *PFN_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI *PFN_UnmapViewOfFile)(LPCVOID);
typedef PVOID (WINAPI *PFN_MapViewOfFile3)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, void *, ULONG);
typedef BOOL (WINAPI *PFN_UnmapViewOfFile2)(HANDLE, PVOID, ULONG);
typedef PVOID (WINAPI *PFN_AddVEH)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI *PFN_RemoveVEH)(PVOID);
typedef BOOL (WINAPI *PFN_GetProcessAffinityMask)(HANDLE, PDWORD_PTR, PDWORD_PTR);
typedef BOOL (WINAPI *PFN_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX);

struct NnOsVersion {
    ULONG size, major, minor, build, platform;
    WCHAR csd[128];
};
typedef LONG (NTAPI *PFN_RtlGetVersion)(NnOsVersion *);

struct ProcHit {
    FARPROC p;
    const char *mod;
};

static HMODULE get_mod(const wchar_t *n)
{
    HMODULE m = nullptr;
    GetModuleHandleExW(0, n, &m);
    return m;
}

static ProcHit find_proc(const char *name)
{
    static const wchar_t *mods[] = {L"kernelbase.dll", L"kernel32.dll", L"ntdll.dll"};
    static const char *modn[] = {"kernelbase", "kernel32", "ntdll"};
    for (int i = 0; i < 3; i++) {
        HMODULE m = get_mod(mods[i]);
        if (m) {
            FARPROC p = GetProcAddress(m, name);
            if (p)
                return ProcHit{p, modn[i]};
        }
    }
    return ProcHit{nullptr, "-"};
}

template <class T> static T fn(const char *name) { return (T)(void *)find_proc(name).p; }

struct Api {
    PFN_VirtualAlloc2 VirtualAlloc2 = nullptr, VirtualAlloc2FromApp = nullptr;
    PFN_VirtualAllocFromApp VirtualAllocFromApp = nullptr;
    PFN_VirtualAlloc VirtualAlloc_ = nullptr;
    PFN_VirtualProtectFromApp VirtualProtectFromApp = nullptr;
    PFN_VirtualProtect VirtualProtect_ = nullptr;
    PFN_VirtualFree VirtualFree_ = nullptr;
    PFN_CreateFileMappingFromApp CreateFileMappingFromApp = nullptr;
    PFN_MapViewOfFileFromApp MapViewOfFileFromApp = nullptr;
    PFN_CreateFileMappingW CreateFileMappingW_ = nullptr;
    PFN_MapViewOfFile MapViewOfFile_ = nullptr;
    PFN_UnmapViewOfFile UnmapViewOfFile_ = nullptr;
    PFN_MapViewOfFile3 MapViewOfFile3 = nullptr, MapViewOfFile3FromApp = nullptr;
    PFN_UnmapViewOfFile2 UnmapViewOfFile2 = nullptr;
    PFN_AddVEH AddVEH = nullptr;
    PFN_RemoveVEH RemoveVEH = nullptr;
    bool resolved = false;
};
static Api g;

static void resolve_api()
{
    if (g.resolved)
        return;
    g.VirtualAlloc2 = fn<PFN_VirtualAlloc2>("VirtualAlloc2");
    g.VirtualAlloc2FromApp = fn<PFN_VirtualAlloc2>("VirtualAlloc2FromApp");
    g.VirtualAllocFromApp = fn<PFN_VirtualAllocFromApp>("VirtualAllocFromApp");
    g.VirtualAlloc_ = fn<PFN_VirtualAlloc>("VirtualAlloc");
    g.VirtualProtectFromApp = fn<PFN_VirtualProtectFromApp>("VirtualProtectFromApp");
    g.VirtualProtect_ = fn<PFN_VirtualProtect>("VirtualProtect");
    g.VirtualFree_ = fn<PFN_VirtualFree>("VirtualFree");
    g.CreateFileMappingFromApp = fn<PFN_CreateFileMappingFromApp>("CreateFileMappingFromApp");
    g.MapViewOfFileFromApp = fn<PFN_MapViewOfFileFromApp>("MapViewOfFileFromApp");
    g.CreateFileMappingW_ = fn<PFN_CreateFileMappingW>("CreateFileMappingW");
    g.MapViewOfFile_ = fn<PFN_MapViewOfFile>("MapViewOfFile");
    g.UnmapViewOfFile_ = fn<PFN_UnmapViewOfFile>("UnmapViewOfFile");
    g.MapViewOfFile3 = fn<PFN_MapViewOfFile3>("MapViewOfFile3");
    g.MapViewOfFile3FromApp = fn<PFN_MapViewOfFile3>("MapViewOfFile3FromApp");
    g.UnmapViewOfFile2 = fn<PFN_UnmapViewOfFile2>("UnmapViewOfFile2");
    g.AddVEH = fn<PFN_AddVEH>("AddVectoredExceptionHandler");
    g.RemoveVEH = fn<PFN_RemoveVEH>("RemoveVectoredExceptionHandler");
    g.resolved = true;
}

static const SIZE_T PG = 4096;

static HANDLE cur() { return GetCurrentProcess(); }

// Wrappers: prefer the UWP-sanctioned *FromApp entry point, fall back to the
// desktop one (only so the console harness works under Wine).
static void *valloc(SIZE_T size, ULONG type, ULONG prot)
{
    if (g.VirtualAllocFromApp)
        return g.VirtualAllocFromApp(nullptr, size, type, prot);
    if (g.VirtualAlloc_)
        return g.VirtualAlloc_(nullptr, size, type, prot);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return nullptr;
}

static bool vprotect(void *p, SIZE_T size, ULONG prot)
{
    ULONG old = 0;
    if (g.VirtualProtectFromApp)
        return g.VirtualProtectFromApp(p, size, prot, &old) != 0;
    if (g.VirtualProtect_)
        return g.VirtualProtect_(p, size, prot, (PDWORD)&old) != 0;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return false;
}

static bool vfree(void *p, SIZE_T size, DWORD type)
{
    return g.VirtualFree_ && g.VirtualFree_(p, size, type);
}

static void *alloc2(SIZE_T size, ULONG type, ULONG prot, void *addr = nullptr)
{
    if (g.VirtualAlloc2FromApp)
        return g.VirtualAlloc2FromApp(cur(), addr, size, type, prot, nullptr, 0);
    if (g.VirtualAlloc2)
        return g.VirtualAlloc2(cur(), addr, size, type, prot, nullptr, 0);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return nullptr;
}

static void *map3(HANDLE sec, void *at, uint64_t off, SIZE_T size, ULONG alloc, ULONG prot)
{
    if (g.MapViewOfFile3FromApp)
        return g.MapViewOfFile3FromApp(sec, cur(), at, off, size, alloc, prot, nullptr, 0);
    if (g.MapViewOfFile3)
        return g.MapViewOfFile3(sec, cur(), at, off, size, alloc, prot, nullptr, 0);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return nullptr;
}

static bool have_placeholders() { return (g.VirtualAlloc2FromApp || g.VirtualAlloc2) && (g.MapViewOfFile3FromApp || g.MapViewOfFile3) && g.UnmapViewOfFile2 && g.VirtualFree_; }

// ------------------------------------------------------------ result store --

struct Results {
    // JIT
    bool jit_dualmap = false;
    double jit_call_ns = -1, icache_flush_ns = -1, toggle_pair_ns = -1;
    bool rwx_direct = false, rw_to_rx = false;
    // placeholders
    bool ph_api = false, ph_4k_views = false, ph_alias = false;
    double split_ns = -1, map_ns = -1, unmap_ns = -1, protect_ns = -1, softfault_ns = -1;
    uint64_t max_views = 0;
    bool views_capped = false;
    // faults
    double fault_protect_ns = -1, fault_map_ns = -1, raise_ns = -1, protect_only_ns = -1;
    // VA
    double max_single_va_gb = -1, total_va_gb = -1;
    // benches
    double tlb_chase_ratio = -1, tlb_rand_ratio = -1, reloc_chase_ratio = -1, reloc_rand_ratio = -1; // 256 KB (cache-resident)
    double tlb_chase_mid = -1, tlb_rand_mid = -1;                                                       // 8 MB (L3/DRAM-bound)
    double ibtc_pred_ratio = -1, ibtc_unpred_ratio = -1;
    // fsgsbase
    int fsgsbase = -1; // -1 unknown, 0 #UD, 1 works
};
static Results R;

// ----------------------------------------------------------- 0. environment --

static void probe_env()
{
    L("== 0. Environment ==");
    PFN_RtlGetVersion rgv = fn<PFN_RtlGetVersion>("RtlGetVersion");
    if (rgv) {
        NnOsVersion v;
        memset(&v, 0, sizeof(v));
        v.size = sizeof(v);
        if (rgv(&v) == 0)
            S("OS: Windows %lu.%lu build %lu", (unsigned long)v.major, (unsigned long)v.minor, (unsigned long)v.build);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    S("Logical CPUs: %lu   page %lu B   alloc granularity %lu B", (unsigned long)si.dwNumberOfProcessors, (unsigned long)si.dwPageSize, (unsigned long)si.dwAllocationGranularity);
    S("App VA range: %p .. %p  (%.1f TB usable)", si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress, (double)((uintptr_t)si.lpMaximumApplicationAddress) / 1099511627776.0);

    PFN_GetProcessAffinityMask gpam = fn<PFN_GetProcessAffinityMask>("GetProcessAffinityMask");
    if (gpam) {
        DWORD_PTR pm = 0, sm = 0;
        if (gpam(cur(), &pm, &sm)) {
            int bits = 0;
            for (DWORD_PTR m = pm; m; m >>= 1)
                bits += (int)(m & 1);
            L("Process affinity mask: 0x%llx (%d cores usable), system mask 0x%llx", (unsigned long long)pm, bits, (unsigned long long)sm);
        }
    }

    PFN_GlobalMemoryStatusEx gms = fn<PFN_GlobalMemoryStatusEx>("GlobalMemoryStatusEx");
    if (gms) {
        MEMORYSTATUSEX ms;
        memset(&ms, 0, sizeof(ms));
        ms.dwLength = sizeof(ms);
        if (gms(&ms))
            L("Memory: phys avail %.0f MB / %.0f MB, commit avail %.0f MB, virtual avail %.1f GB", ms.ullAvailPhys / 1048576.0, ms.ullTotalPhys / 1048576.0, ms.ullAvailPageFile / 1048576.0, ms.ullAvailVirtual / 1073741824.0);
    }

    // CPUID
    int r[4];
    __cpuid(r, 0);
    int maxLeaf = r[0];
    char vendor[13];
    memcpy(vendor, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    vendor[12] = 0;
    char brand[49] = {0};
    for (int i = 0; i < 3; i++) {
        __cpuid(r, 0x80000002 + i);
        memcpy(brand + 16 * i, r, 16);
    }
    __cpuid(r, 1);
    int eax1 = r[0], ecx1 = r[2], edx1 = r[3];
    int fam = (eax1 >> 8) & 0xf, mod = (eax1 >> 4) & 0xf, step = eax1 & 0xf;
    if (fam == 0xf)
        fam += (eax1 >> 20) & 0xff;
    if (fam >= 6)
        mod += ((eax1 >> 16) & 0xf) << 4;
    S("CPU: %s | %s", vendor, brand);
    L("  family 0x%x model 0x%x stepping %d, max leaf 0x%x", fam, mod, step, maxLeaf);
    int ebx7 = 0, ecx7 = 0;
    if (maxLeaf >= 7) {
        __cpuidex(r, 7, 0);
        ebx7 = r[1];
        ecx7 = r[2];
    }
    __cpuid(r, 0x80000001);
    int ecx81 = r[2], edx81 = r[3];
    __cpuid(r, 0x80000000);
    int maxExt = r[0];
    int edx87 = 0;
    if ((unsigned)maxExt >= 0x80000007u) {
        __cpuid(r, 0x80000007);
        edx87 = r[3];
    }
    bool osxsave = (ecx1 >> 27) & 1;
    unsigned long long xcr0 = 0;
    if (osxsave)
        xcr0 = _xgetbv(0);
    S("Features: SSE4.2=%d AVX=%d AVX2=%d FMA=%d BMI1=%d BMI2=%d POPCNT=%d AVX512F=%d  XCR0=0x%llx", (ecx1 >> 20) & 1, (ecx1 >> 28) & 1, (ebx7 >> 5) & 1, (ecx1 >> 12) & 1, (ebx7 >> 3) & 1, (ebx7 >> 8) & 1, (ecx1 >> 23) & 1, (ebx7 >> 16) & 1, xcr0);
    L("  FSGSBASE(cpu)=%d SMEP=%d SMAP=%d UMIP=%d RDTSCP=%d invariantTSC=%d NX=%d 1GBpages=%d SSE4A=%d CX16=%d", ebx7 & 1, (ebx7 >> 7) & 1, (ebx7 >> 20) & 1, (ecx7 >> 2) & 1, (edx81 >> 27) & 1, (edx87 >> 8) & 1, (edx81 >> 20) & 1, (edx81 >> 26) & 1, (ecx81 >> 6) & 1, (ecx1 >> 13) & 1);
    (void)edx1;
    bool hv = (ecx1 >> 31) & 1;
    if (hv) {
        __cpuid(r, 0x40000000);
        char hvv[13];
        memcpy(hvv, &r[1], 4);
        memcpy(hvv + 4, &r[2], 4);
        memcpy(hvv + 8, &r[3], 4);
        hvv[12] = 0;
        S("Hypervisor present: yes, vendor '%s', max leaf 0x%x", hvv, r[0]);
    } else {
        S("Hypervisor present: no (CPUID bit clear)");
    }

    // TSC frequency vs QPC
    uint64_t q0 = qpc();
    unsigned long long t0 = __rdtsc();
    while (ns_since(q0) < 100e6) {
    }
    unsigned long long t1 = __rdtsc();
    double sec = ns_since(q0) / 1e9;
    L("TSC ~ %.0f MHz (QPC %.0f MHz)", (double)(t1 - t0) / sec / 1e6, qpc_freq() / 1e6);
}

// --------------------------------------------------------- 1. API matrix ----

static void probe_api_matrix()
{
    L("");
    L("== 1. API availability (resolved via GetProcAddress in kernelbase/kernel32/ntdll) ==");
    static const char *names[] = {
        "VirtualAlloc2", "VirtualAlloc2FromApp", "MapViewOfFile3", "MapViewOfFile3FromApp", "UnmapViewOfFile2", "VirtualAllocFromApp", "VirtualProtectFromApp",
        "CreateFileMappingFromApp", "MapViewOfFileFromApp", "AddVectoredExceptionHandler", "AddVectoredContinueHandler", "RtlAddFunctionTable", "RtlInstallFunctionTableCallback",
        "RtlLookupFunctionEntry", "RtlVirtualUnwind", "RtlUnwindEx", "RtlRestoreContext", "RtlCaptureContext", "SetThreadStackGuarantee", "GetThreadContext", "SetThreadContext",
        "SuspendThread", "FlushInstructionCache", "CreateWaitableTimerExW", "GetProcessMitigationPolicy", "NtAllocateVirtualMemory", "NtMapViewOfSection", "NtProtectVirtualMemory",
        "NtQueryVirtualMemory", "NtContinue", "NtRaiseException", "NtSetInformationVirtualMemory", "NtQuerySystemInformation", "KiUserExceptionDispatcher"};
    int missing = 0;
    for (const char *n : names) {
        ProcHit h = find_proc(n);
        L("  %-34s %s", n, h.p ? h.mod : "MISSING");
        if (!h.p)
            missing++;
    }
    S("API matrix: %d of %d entry points missing (full list in report)", missing, (int)(sizeof(names) / sizeof(names[0])));
    S("Placeholder APIs (VirtualAlloc2*/MapViewOfFile3*/UnmapViewOfFile2): %s", have_placeholders() ? "present" : "MISSING");
}

// ----------------------------------------------- section / JIT buffer helpers --

struct JitBuf {
    HANDLE sec = nullptr;
    uint8_t *rw = nullptr, *rx = nullptr;
    SIZE_T size = 0;
    const char *api = "";
};

static HANDLE create_section(SIZE_T size, ULONG prot, const char **api)
{
    HANDLE h = nullptr;
    if (g.CreateFileMappingFromApp) {
        h = g.CreateFileMappingFromApp(INVALID_HANDLE_VALUE, nullptr, prot, (ULONG64)size, nullptr);
        if (h) {
            *api = "CreateFileMappingFromApp";
            return h;
        }
    }
    if (g.CreateFileMappingW_) {
        h = g.CreateFileMappingW_(INVALID_HANDLE_VALUE, nullptr, prot, (DWORD)((uint64_t)size >> 32), (DWORD)size, nullptr);
        if (h)
            *api = "CreateFileMappingW";
    }
    return h;
}

static void *map_view(HANDLE sec, ULONG access, SIZE_T size)
{
    if (g.MapViewOfFileFromApp) {
        void *p = g.MapViewOfFileFromApp(sec, access, 0, size);
        if (p)
            return p;
    }
    if (g.MapViewOfFile_)
        return g.MapViewOfFile_(sec, access, 0, 0, size);
    return nullptr;
}

static bool jit_create(JitBuf &b, SIZE_T size)
{
    b.size = size;
    b.sec = create_section(size, PAGE_EXECUTE_READWRITE, &b.api);
    if (!b.sec) {
        L("  section(PAGE_EXECUTE_READWRITE) failed, err %lu", (unsigned long)GetLastError());
        return false;
    }
    b.rw = (uint8_t *)map_view(b.sec, FILE_MAP_WRITE, size);
    if (!b.rw) {
        L("  RW view failed, err %lu", (unsigned long)GetLastError());
        return false;
    }
    b.rx = (uint8_t *)map_view(b.sec, FILE_MAP_READ | FILE_MAP_EXECUTE, size);
    if (!b.rx) {
        L("  RX view (FILE_MAP_EXECUTE) failed, err %lu", (unsigned long)GetLastError());
        return false;
    }
    return true;
}

static void jit_destroy(JitBuf &b)
{
    if (g.UnmapViewOfFile_) {
        if (b.rw)
            g.UnmapViewOfFile_(b.rw);
        if (b.rx)
            g.UnmapViewOfFile_(b.rx);
    }
    if (b.sec)
        CloseHandle(b.sec);
    b = JitBuf();
}

typedef uint32_t (*jit_fn)(uint32_t);

// ------------------------------------------------- 2. executable memory ------

static void probe_jit()
{
    L("");
    L("== 2. Executable memory (what a translator's code cache needs) ==");
    static const uint8_t stub_p1[] = {0x8D, 0x41, 0x01, 0xC3}; // lea eax,[rcx+1]; ret
    static const uint8_t stub_p2[] = {0x8D, 0x41, 0x02, 0xC3}; // lea eax,[rcx+2]; ret

    void *p = valloc(65536, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    R.rwx_direct = p != nullptr;
    L("  VirtualAlloc(FromApp) PAGE_EXECUTE_READWRITE: %s (err %lu)", p ? "ALLOWED" : "denied", (unsigned long)(p ? 0 : GetLastError()));
    if (p)
        vfree(p, 0, MEM_RELEASE);

    p = valloc(65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p) {
        memcpy(p, stub_p1, sizeof(stub_p1));
        bool ok = vprotect(p, 4096, PAGE_EXECUTE_READ);
        R.rw_to_rx = ok;
        L("  RW -> PAGE_EXECUTE_READ via VirtualProtect(FromApp): %s (err %lu)", ok ? "ALLOWED" : "denied", (unsigned long)(ok ? 0 : GetLastError()));
        if (ok) {
            FlushInstructionCache(cur(), p, sizeof(stub_p1));
            jit_fn f = (jit_fn)p;
            L("  executing the toggled page: f(7)=%u (expect 8)", (unsigned)f(7));
            const int N = 20000;
            uint64_t t0 = qpc();
            for (int i = 0; i < N; i++) {
                vprotect(p, 4096, PAGE_READWRITE);
                vprotect(p, 4096, PAGE_EXECUTE_READ);
            }
            R.toggle_pair_ns = ns_since(t0) / N;
            L("  RW<->RX toggle pair: %.0f ns", R.toggle_pair_ns);
            vprotect(p, 4096, PAGE_READWRITE);
        }
        vfree(p, 0, MEM_RELEASE);
    }

    JitBuf b;
    if (!jit_create(b, 65536)) {
        S("JIT dual mapping (RW view + RX view): FAILED");
        jit_destroy(b);
        return;
    }
    L("  section via %s; RW view %p, RX view %p", b.api, (void *)b.rw, (void *)b.rx);
    memcpy(b.rw, stub_p1, sizeof(stub_p1));
    FlushInstructionCache(cur(), b.rx, sizeof(stub_p1));
    jit_fn f = (jit_fn)b.rx;
    uint32_t v1 = f(41);
    memcpy(b.rw, stub_p2, sizeof(stub_p2)); // patch through the RW alias
    FlushInstructionCache(cur(), b.rx, sizeof(stub_p2));
    uint32_t v2 = f(41);
    L("  stub via RX view: f(41)=%u (expect 42); after patching through RW alias: %u (expect 43)", (unsigned)v1, (unsigned)v2);
    R.jit_dualmap = (v1 == 42 && v2 == 43);

    const uint64_t CN = 20000000;
    uint32_t x = 0;
    uint64_t t0 = qpc();
    for (uint64_t i = 0; i < CN; i++)
        x = f(x);
    R.jit_call_ns = ns_since(t0) / CN;
    (void)x;

    const int FN = 200000;
    t0 = qpc();
    for (int i = 0; i < FN; i++)
        FlushInstructionCache(cur(), b.rx, 64);
    R.icache_flush_ns = ns_since(t0) / FN;

    S("JIT dual mapping (RW+RX views): %s   call %.2f ns   FlushInstructionCache %.0f ns/call", R.jit_dualmap ? "OK" : "BROKEN", R.jit_call_ns, R.icache_flush_ns);
    S("  direct RWX alloc: %s   RW->RX VirtualProtect: %s", R.rwx_direct ? "allowed" : "denied", R.rw_to_rx ? "allowed" : "denied");
    jit_destroy(b);
}

// ----------------------------------------- 3. 4 KB views via placeholders ----

struct PhCtx {
    HANDLE sec = nullptr;
    SIZE_T secBytes = 0;
};

static bool split_pages(uint8_t *base, size_t pages)
{
    for (size_t i = 0; i + 1 < pages; i++) {
        if (!vfree(base + i * PG, PG, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
            L("    split failed at page %llu, err %lu", (unsigned long long)i, (unsigned long)GetLastError());
            return false;
        }
    }
    return true;
}

static void release_region(uint8_t *base, size_t pages)
{
    if (vfree(base, pages * PG, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
        vfree(base, 0, MEM_RELEASE);
        return;
    }
    for (size_t i = 0; i < pages; i++)
        vfree(base + i * PG, 0, MEM_RELEASE);
}

static void unmap_pages(uint8_t *base, size_t pages)
{
    if (!g.UnmapViewOfFile2)
        return;
    for (size_t i = 0; i < pages; i++)
        g.UnmapViewOfFile2(cur(), base + i * PG, MEM_PRESERVE_PLACEHOLDER);
}

static void probe_placeholders(PhCtx &ctx)
{
    L("");
    L("== 3. Page-granular (4 KB) views through placeholders ==");
    R.ph_api = have_placeholders();
    if (!R.ph_api) {
        S("4 KB views: SKIPPED (placeholder APIs missing)");
        return;
    }
    const SIZE_T SECB = 64ull << 20;
    const char *api = "";
    ctx.sec = create_section(SECB, PAGE_READWRITE, &api);
    ctx.secBytes = SECB;
    if (!ctx.sec) {
        S("4 KB views: FAILED to create a 64 MB pagefile-backed section (err %lu)", (unsigned long)GetLastError());
        return;
    }
    L("  64 MB pagefile-backed section via %s", api);

    // Step 1: correctness, at a base and an offset that are NOT 64 KB aligned.
    {
        uint8_t *base = (uint8_t *)alloc2(1 << 20, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
        if (!base) {
            S("4 KB views: FAILED at placeholder reserve (err %lu)", (unsigned long)GetLastError());
            return;
        }
        L("  reserved 1 MB placeholder at %p", (void *)base);
        bool s1 = vfree(base + 3 * PG, PG, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        DWORD e1 = GetLastError();
        bool s2 = vfree(base + 9 * PG, PG, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        DWORD e2 = GetLastError();
        L("  split page 3: %s (err %lu)   split page 9: %s (err %lu)", s1 ? "ok" : "FAILED", (unsigned long)(s1 ? 0 : e1), s2 ? "ok" : "FAILED", (unsigned long)(s2 ? 0 : e2));
        uint8_t *v1 = s1 ? (uint8_t *)map3(ctx.sec, base + 3 * PG, 0x5000, PG, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE) : nullptr;
        DWORD e3 = GetLastError();
        uint8_t *v2 = s2 ? (uint8_t *)map3(ctx.sec, base + 9 * PG, 0x5000, PG, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE) : nullptr;
        DWORD e4 = GetLastError();
        L("  map 4 KB view @base+0x3000 (section offset 0x5000): %s (err %lu)", v1 ? "ok" : "FAILED", (unsigned long)(v1 ? 0 : e3));
        L("  map 4 KB view @base+0x9000 (same section offset):   %s (err %lu)", v2 ? "ok" : "FAILED", (unsigned long)(v2 ? 0 : e4));
        R.ph_4k_views = v1 && v2;
        if (v1 && v2) {
            v1[0x10] = 0xA5;
            bool a = v2[0x10] == 0xA5;
            v2[0x20] = 0x5A;
            bool bb = v1[0x20] == 0x5A;
            R.ph_alias = a && bb;
            L("  two views of one physical page see each other's writes: %s", R.ph_alias ? "YES (true aliasing)" : "NO");
        }
        if (v1 && g.UnmapViewOfFile2)
            g.UnmapViewOfFile2(cur(), v1, MEM_PRESERVE_PLACEHOLDER);
        if (v2 && g.UnmapViewOfFile2)
            g.UnmapViewOfFile2(cur(), v2, MEM_PRESERVE_PLACEHOLDER);
        if (vfree(base, 1 << 20, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS))
            vfree(base, 0, MEM_RELEASE);
        else
            L("  (cleanup: coalesce failed, err %lu; leaking 1 MB of VA)", (unsigned long)GetLastError());
    }
    S("4 KB-granular views at non-64KB base/offset: %s   true aliasing: %s", R.ph_4k_views ? "YES" : "NO", R.ph_alias ? "YES" : "NO");
    if (!R.ph_4k_views) {
        L("  -> the page-granular shadow-paging design is not available on this host; skipping bulk tests");
        return;
    }

    // Step 2: per-operation costs on 16384 pages (64 MB).
    const size_t N = 16384;
    uint8_t *base = (uint8_t *)alloc2(N * PG, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    if (!base) {
        L("  bulk: reserve failed err %lu", (unsigned long)GetLastError());
        return;
    }
    uint64_t t0 = qpc();
    bool ok = split_pages(base, N);
    R.split_ns = ns_since(t0) / N;
    size_t mapped = 0;
    if (ok) {
        t0 = qpc();
        for (size_t i = 0; i < N; i++) {
            if (!map3(ctx.sec, base + i * PG, ((uint64_t)i * PG) % ctx.secBytes, PG, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE)) {
                L("    map failed at page %llu, err %lu", (unsigned long long)i, (unsigned long)GetLastError());
                break;
            }
            mapped++;
        }
        R.map_ns = ns_since(t0) / (mapped ? mapped : 1);
    }
    if (mapped == N) {
        t0 = qpc();
        for (size_t i = 0; i < N; i++)
            ((volatile uint8_t *)base)[i * PG] = (uint8_t)i;
        R.softfault_ns = ns_since(t0) / N;

        t0 = qpc();
        for (size_t i = 0; i < N; i++)
            vprotect(base + i * PG, PG, PAGE_READONLY);
        for (size_t i = 0; i < N; i++)
            vprotect(base + i * PG, PG, PAGE_READWRITE);
        R.protect_ns = ns_since(t0) / (2.0 * N);

        t0 = qpc();
        unmap_pages(base, N);
        R.unmap_ns = ns_since(t0) / N;
    } else {
        unmap_pages(base, mapped);
    }
    release_region(base, N);
    S("4 KB view ops (ns/page): split %.0f   map %.0f   unmap %.0f   protect %.0f   first-touch(native) %.0f", R.split_ns, R.map_ns, R.unmap_ns, R.protect_ns, R.softfault_ns);
}

// How many separate 4 KB views can the process hold? (each is its own VAD)
static void probe_view_scale(PhCtx &ctx)
{
    if (!R.ph_4k_views || !ctx.sec)
        return;
    L("");
    L("  -- view-count scaling (each 4 KB view is a separate VAD; 16384 views per 64 MB region) --");
    const size_t RN = 16384, MAXREG = 16;
    std::vector<uint8_t *> regions;
    std::vector<size_t> mappedPer;
    uint64_t views = 0, tAll = qpc();
    for (size_t k = 0; k < MAXREG; k++) {
        uint8_t *base = (uint8_t *)alloc2(RN * PG, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
        if (!base) {
            L("    region %2llu: reserve failed, err %lu", (unsigned long long)k, (unsigned long)GetLastError());
            break;
        }
        regions.push_back(base);
        mappedPer.push_back(0);
        uint64_t t0 = qpc();
        if (!split_pages(base, RN))
            break;
        double splitNs = ns_since(t0) / RN;
        t0 = qpc();
        size_t ok = 0;
        for (size_t i = 0; i < RN; i++) {
            if (!map3(ctx.sec, base + i * PG, ((uint64_t)i * PG) % ctx.secBytes, PG, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE)) {
                L("    region %2llu: map failed at view %llu, err %lu", (unsigned long long)k, (unsigned long long)i, (unsigned long)GetLastError());
                break;
            }
            ok++;
        }
        mappedPer.back() = ok;
        views += ok;
        L("    region %2llu: %7llu views live, split %.0f ns/page, map %.0f ns/page", (unsigned long long)k, (unsigned long long)views, splitNs, ns_since(t0) / (ok ? ok : 1));
        if (ok < RN)
            break;
        if (ns_since(tAll) > 25e9) {
            L("    time budget reached");
            R.views_capped = true;
            break;
        }
    }
    R.max_views = views;
    if (regions.size() == MAXREG)
        R.views_capped = true;
    for (size_t k = 0; k < regions.size(); k++) {
        unmap_pages(regions[k], mappedPer[k]);
        release_region(regions[k], RN);
    }
    S("Live 4 KB views reached: %llu%s", (unsigned long long)views, R.views_capped ? " (hit my safety cap, not a system limit)" : " (stopped by a failure)");
}

// ------------------------------------------------------ vectored exceptions --

struct VehState {
    volatile LONG mode;
    uint8_t *lo, *hi;
    HANDLE sec;
    uint64_t secBytes;
    volatile LONG64 faults, failures;
    uintptr_t stubLo, stubHi, recoverRip;
    LONG skipLen;
    volatile LONG stubHit;
    volatile DWORD stubCode;
    volatile uintptr_t stubRsp;
    volatile LONG rspInStack;
};
static VehState V;

static LONG NTAPI veh(PEXCEPTION_POINTERS ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    switch (V.mode) {
    case 1: // AV on a committed PAGE_NOACCESS page -> make it RW
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            uint8_t *a = (uint8_t *)er->ExceptionInformation[1];
            if (a >= V.lo && a < V.hi) {
                uint8_t *pg = (uint8_t *)((uintptr_t)a & ~(uintptr_t)(PG - 1));
                if (vprotect(pg, PG, PAGE_READWRITE)) {
                    V.faults++;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                V.failures++;
            }
        }
        break;
    case 2: // AV on a 4 KB placeholder -> map a view there (shadow-paging first touch)
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            uint8_t *a = (uint8_t *)er->ExceptionInformation[1];
            if (a >= V.lo && a < V.hi) {
                uint8_t *pg = (uint8_t *)((uintptr_t)a & ~(uintptr_t)(PG - 1));
                uint64_t off = ((uint64_t)(pg - V.lo)) % V.secBytes;
                if (map3(V.sec, pg, off, PG, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE)) {
                    V.faults++;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                V.failures++;
            }
        }
        break;
    case 3: // software exception baseline
        if (er->ExceptionCode == 0xE0000001u) {
            V.faults++;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        break;
    case 4: { // fault inside one of our machine-code stubs: record, then resume at a known place
        uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
        if (rip >= V.stubLo && rip < V.stubHi) {
            V.stubHit++;
            V.stubCode = er->ExceptionCode;
            V.stubRsp = (uintptr_t)ep->ContextRecord->Rsp;
            NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
            V.rspInStack = ((uintptr_t)ep->ContextRecord->Rsp >= (uintptr_t)tib->StackLimit && (uintptr_t)ep->ContextRecord->Rsp < (uintptr_t)tib->StackBase) ? 1 : 0;
            if (V.skipLen > 0) {
                ep->ContextRecord->Rip += V.skipLen;
                ep->ContextRecord->Rax = 0;
            } else {
                ep->ContextRecord->Rsp = ep->ContextRecord->Rax; // stubs keep the old rsp in rax
                ep->ContextRecord->Rip = V.recoverRip;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } break;
    case 5: { // fault while in/around 32-bit compatibility mode
        uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
        if (rip >= V.stubLo && rip < V.stubHi) {
            V.stubHit++;
            V.stubCode = er->ExceptionCode;
            V.stubRsp = (uintptr_t)ep->ContextRecord->Rsp;
            ep->ContextRecord->SegCs = 0x33;
            ep->ContextRecord->Rsp = ep->ContextRecord->Rbx; // entry stub saved rsp in rbx
            ep->ContextRecord->Rax = 0xDEAD0001u;
            ep->ContextRecord->Rip = V.recoverRip;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } break;
    default:
        break;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static PVOID install_veh() { return g.AddVEH ? g.AddVEH(1, veh) : nullptr; }
static void remove_veh(PVOID h)
{
    if (h && g.RemoveVEH)
        g.RemoveVEH(h);
    V.mode = 0;
}

// -------------------------------------------------------- 4. fault timing ----

static void probe_faults(PhCtx &ctx)
{
    L("");
    L("== 4. Fault round trips (the cost of lazy shadow paging) ==");
    PVOID h = install_veh();
    if (!h) {
        S("Fault timing: SKIPPED (no vectored exception handlers)");
        return;
    }
    const size_t N = 16384;

    L("  A: first touch of a committed PAGE_NOACCESS page; handler flips it to RW");
    uint8_t *reg = (uint8_t *)valloc(N * PG, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    if (reg) {
        memset(&V, 0, sizeof(V));
        V.lo = reg;
        V.hi = reg + N * PG;
        V.mode = 1;
        uint64_t t0 = qpc();
        for (size_t i = 0; i < N; i++)
            ((volatile uint8_t *)reg)[i * PG] = 1;
        double tot = ns_since(t0);
        V.mode = 0;
        R.fault_protect_ns = tot / N;
        L("     %.0f ns per fault (%lld handled, %lld handler failures)", R.fault_protect_ns, (long long)V.faults, (long long)V.failures);
        uint64_t t1 = qpc();
        for (size_t i = 0; i < N; i++)
            vprotect(reg + i * PG, PG, PAGE_NOACCESS);
        for (size_t i = 0; i < N; i++)
            vprotect(reg + i * PG, PG, PAGE_READWRITE);
        R.protect_only_ns = ns_since(t1) / (2.0 * N);
        L("     (the VirtualProtect call alone costs %.0f ns, so exception dispatch ~ %.0f ns)", R.protect_only_ns, R.fault_protect_ns - R.protect_only_ns);
        vfree(reg, 0, MEM_RELEASE);
    } else {
        L("     skipped: could not allocate test region (err %lu)", (unsigned long)GetLastError());
    }

    L("  B: first touch of a 4 KB placeholder; handler maps a 4 KB view of the shared section (this IS shadow-paging's hot path)");
    if (ctx.sec && R.ph_4k_views) {
        uint8_t *base = (uint8_t *)alloc2(N * PG, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
        if (base && split_pages(base, N)) {
            memset(&V, 0, sizeof(V));
            V.lo = base;
            V.hi = base + N * PG;
            V.sec = ctx.sec;
            V.secBytes = ctx.secBytes;
            V.mode = 2;
            L("     (if the app dies right here, mapping from inside an exception handler is not survivable)");
            uint64_t t0 = qpc();
            for (size_t i = 0; i < N; i++)
                ((volatile uint8_t *)base)[i * PG] = 1;
            double tot = ns_since(t0);
            V.mode = 0;
            R.fault_map_ns = tot / N;
            L("     %.0f ns per fault (%lld handled, %lld handler failures)", R.fault_map_ns, (long long)V.faults, (long long)V.failures);
            unmap_pages(base, N);
            release_region(base, N);
        } else if (base) {
            release_region(base, N);
        }
    } else {
        L("     skipped (no 4 KB views on this host)");
    }

    L("  C: baseline - RaiseException + handler returning CONTINUE_EXECUTION (no page fault involved)");
    memset(&V, 0, sizeof(V));
    V.mode = 3;
    const int RN = 20000;
    uint64_t t0 = qpc();
    for (int i = 0; i < RN; i++)
        RaiseException(0xE0000001u, 0, 0, nullptr);
    R.raise_ns = ns_since(t0) / RN;
    V.mode = 0;
    L("     %.0f ns per software exception", R.raise_ns);

    remove_veh(h);
    char fm[32], fp[32];
    if (R.fault_map_ns >= 0) snprintf(fm, sizeof(fm), "%.2f us", R.fault_map_ns / 1000.0); else snprintf(fm, sizeof(fm), "n/a");
    if (R.fault_protect_ns >= 0) snprintf(fp, sizeof(fp), "%.2f us", R.fault_protect_ns / 1000.0); else snprintf(fp, sizeof(fp), "n/a");
    S("Fault round trip: AV+protect %s | AV+map 4KB view %s | bare software exception %.2f us", fp, fm, R.raise_ns / 1000.0);
}

// ------------------------------------------------------ 5. VA limits ---------

static void probe_va()
{
    L("");
    L("== 5. Address-space limits (how big can a guest 'window' be?) ==");
#if !defined(_MSC_VER)
    if (getenv("NN_SKIP_VA")) { // only the Linux/Wine test harness sets this
        L("  skipped (NN_SKIP_VA set)");
        return;
    }
#endif
    static const struct {
        const char *label;
        uint64_t bytes;
    } sizes[] = {{"1 GB", 1ull << 30}, {"16 GB", 16ull << 30}, {"256 GB", 256ull << 30}, {"1 TB", 1ull << 40}, {"4 TB", 4ull << 40}, {"16 TB", 16ull << 40}, {"32 TB", 32ull << 40}, {"64 TB", 64ull << 40}};
    double maxgb = 0;
    for (const auto &s : sizes) {
        void *p = valloc((SIZE_T)s.bytes, MEM_RESERVE, PAGE_NOACCESS);
        DWORD e = p ? 0 : GetLastError();
        L("  reserve %-7s %s (err %lu)", s.label, p ? "ok" : "FAILED", (unsigned long)e);
        if (p) {
            maxgb = (double)s.bytes / 1073741824.0;
            vfree(p, 0, MEM_RELEASE);
        }
    }
    R.max_single_va_gb = maxgb;
    if (g.VirtualAlloc2FromApp || g.VirtualAlloc2) {
        void *p = alloc2(1ull << 40, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
        L("  1 TB *placeholder* reservation: %s (err %lu)", p ? "ok" : "FAILED", (unsigned long)(p ? 0 : GetLastError()));
        if (p)
            vfree(p, 0, MEM_RELEASE);
    }
    std::vector<void *> chunks;
    for (int i = 0; i < 256; i++) { // cap: 64 TB total
        void *p = valloc((SIZE_T)(256ull << 30), MEM_RESERVE, PAGE_NOACCESS);
        if (!p)
            break;
        chunks.push_back(p);
    }
    R.total_va_gb = (double)chunks.size() * 256.0;
    for (void *p : chunks)
        vfree(p, 0, MEM_RELEASE);
    S("Largest single VA reservation: %.0f GB   total reservable in 256 GB chunks: %.0f GB", R.max_single_va_gb, R.total_va_gb);
}

// ------------------------------------------- 6. engine micro-benchmarks ------
//
// These are not a translator. They are the *inner loop* of one: the same
// memory access pattern, with the address formed (a) natively, (b) by adding a
// window base, (c) through an inline software TLB. The ratios are what a
// translator would pay per access on this CPU.

struct TlbEnt {
    uint64_t tag, addend;
};
static const uint64_t GBASE = 0x00007FF600000000ull;
static const size_t TLB_N = 4096;

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static inline uint64_t rnd()
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

// Models a 4-level page walk: four dependent loads from small tables.
static NN_NOINLINE void tlb_fill(TlbEnt *e, uint64_t gaddr, uint64_t addend, const uint64_t *pt)
{
    uint64_t x = pt[(gaddr >> 39) & 511];
    x = pt[512 + ((x ^ (gaddr >> 30)) & 511)];
    x = pt[1024 + ((x ^ (gaddr >> 21)) & 511)];
    x = pt[1536 + ((x ^ (gaddr >> 12)) & 511)];
    e->tag = gaddr >> 12;
    e->addend = addend + (x >> 63); // x < 2^63 by construction; keeps the walk on the dependency chain
}

static NN_NOINLINE uint64_t k_chase_direct(const uint64_t *arr, uint64_t i, uint64_t iters)
{
    for (uint64_t n = 0; n < iters; n++)
        i = arr[i];
    return i;
}

static NN_NOINLINE uint64_t k_chase_reloc(const uint8_t *base, uint64_t gaddr, uint64_t iters)
{
    for (uint64_t n = 0; n < iters; n++)
        gaddr = *(const uint64_t *)(base + gaddr);
    return gaddr;
}

static NN_NOINLINE uint64_t k_chase_tlb(TlbEnt *tlb, const uint64_t *pt, uint64_t addend, uint64_t gaddr, uint64_t iters, uint64_t *misses)
{
    uint64_t miss = 0;
    for (uint64_t n = 0; n < iters; n++) {
        TlbEnt *e = &tlb[(gaddr >> 12) & (TLB_N - 1)];
        if (NN_UNLIKELY(e->tag != (gaddr >> 12))) {
            tlb_fill(e, gaddr, addend, pt);
            miss++;
        }
        gaddr = *(const uint64_t *)(gaddr + e->addend);
    }
    *misses = miss;
    return gaddr;
}

static NN_NOINLINE uint64_t k_rand_direct(const uint64_t *arr, const uint32_t *idx, size_t n)
{
    uint64_t s = 0;
    for (size_t i = 0; i < n; i++)
        s += arr[idx[i]];
    return s;
}

static NN_NOINLINE uint64_t k_rand_reloc(const uint8_t *base, const uint32_t *idx, size_t n)
{
    uint64_t s = 0;
    for (size_t i = 0; i < n; i++)
        s += *(const uint64_t *)(base + ((uint64_t)idx[i] << 3));
    return s;
}

static NN_NOINLINE uint64_t k_rand_tlb(TlbEnt *tlb, const uint64_t *pt, uint64_t addend, const uint32_t *idx, size_t n, uint64_t *misses)
{
    uint64_t s = 0, miss = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t gaddr = GBASE + ((uint64_t)idx[i] << 3);
        TlbEnt *e = &tlb[(gaddr >> 12) & (TLB_N - 1)];
        if (NN_UNLIKELY(e->tag != (gaddr >> 12))) {
            tlb_fill(e, gaddr, addend, pt);
            miss++;
        }
        s += *(const uint64_t *)(gaddr + e->addend);
    }
    *misses = miss;
    return s;
}

static volatile uint64_t g_sink;

static void bench_mem()
{
    L("");
    L("== 6a. Address-translation cost model ==");
    L("   same access pattern, three ways to form the host address:");
    L("   direct = native pointer | reloc = base + guest address (host-MMU window) | tlb = inline 4096-entry direct-mapped software TLB (+ modeled 4-load walk per miss)");
    static const struct {
        const char *name;
        size_t bytes;
        uint64_t chaseIters;
        int randPasses;
    } cfg[] = {{"256 KB", 256u << 10, 30000000ull, 6}, {"8 MB", 8u << 20, 15000000ull, 4}, {"64 MB", 64u << 20, 2500000ull, 2}};

    uint64_t *pt = (uint64_t *)valloc(2048 * 8, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    TlbEnt *tlb = (TlbEnt *)valloc(TLB_N * sizeof(TlbEnt), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    const size_t IDXN = 4u << 20;
    uint32_t *idx = (uint32_t *)valloc(IDXN * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pt || !tlb || !idx) {
        L("  skipped: allocation failed (err %lu)", (unsigned long)GetLastError());
        return;
    }
    for (int i = 0; i < 2048; i++)
        pt[i] = rnd() >> 2;

    for (const auto &c : cfg) {
        size_t n = c.bytes / 8;
        uint64_t *arr = (uint64_t *)valloc(c.bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        uint32_t *perm = (uint32_t *)valloc(n * 4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!arr || !perm) {
            L("  %-6s skipped: allocation failed", c.name);
            if (arr)
                vfree(arr, 0, MEM_RELEASE);
            if (perm)
                vfree(perm, 0, MEM_RELEASE);
            continue;
        }
        for (size_t i = 0; i < n; i++)
            perm[i] = (uint32_t)i;
        for (size_t i = n - 1; i > 0; i--) { // Sattolo: one big cycle, so the chase visits everything
            size_t j = (size_t)(rnd() % i);
            uint32_t t = perm[i];
            perm[i] = perm[j];
            perm[j] = t;
        }
        for (size_t i = 0; i < IDXN; i++)
            idx[i] = (uint32_t)(rnd() % n);
        uint64_t warm = n < 1000000 ? n : 1000000, misses = 0;
        uint64_t t0;

        // ---- dependent loads (latency bound)
        for (size_t i = 0; i < n; i++)
            arr[i] = perm[i];
        g_sink = k_chase_direct(arr, 0, warm);
        t0 = qpc();
        g_sink = k_chase_direct(arr, 0, c.chaseIters);
        double cd = ns_since(t0) / (double)c.chaseIters;

        for (size_t i = 0; i < n; i++)
            arr[i] = (uint64_t)perm[i] << 3;
        g_sink = k_chase_reloc((const uint8_t *)arr, 0, warm);
        t0 = qpc();
        g_sink = k_chase_reloc((const uint8_t *)arr, 0, c.chaseIters);
        double cr = ns_since(t0) / (double)c.chaseIters;

        for (size_t i = 0; i < n; i++)
            arr[i] = GBASE + ((uint64_t)perm[i] << 3);
        uint64_t addend = (uint64_t)(uintptr_t)arr - GBASE;
        for (size_t i = 0; i < TLB_N; i++) {
            tlb[i].tag = ~0ull;
            tlb[i].addend = 0;
        }
        g_sink = k_chase_tlb(tlb, pt, addend, GBASE, n, &misses); // fill pass
        t0 = qpc();
        g_sink = k_chase_tlb(tlb, pt, addend, GBASE, c.chaseIters, &misses);
        double ct = ns_since(t0) / (double)c.chaseIters;
        double cmiss = 100.0 * (double)misses / (double)c.chaseIters;
        L("  %-6s dependent  direct %6.2f ns | reloc %6.2f ns (x%.2f) | tlb %6.2f ns (x%.2f, miss %.1f%%)", c.name, cd, cr, cr / cd, ct, ct / cd, cmiss);

        // ---- independent loads (throughput bound, memory-level parallelism)
        for (size_t i = 0; i < n; i++)
            arr[i] = i;
        size_t total = IDXN * (size_t)c.randPasses;
        g_sink = k_rand_direct(arr, idx, IDXN);
        t0 = qpc();
        for (int p = 0; p < c.randPasses; p++)
            g_sink = k_rand_direct(arr, idx, IDXN);
        double rd = ns_since(t0) / (double)total;

        g_sink = k_rand_reloc((const uint8_t *)arr, idx, IDXN);
        t0 = qpc();
        for (int p = 0; p < c.randPasses; p++)
            g_sink = k_rand_reloc((const uint8_t *)arr, idx, IDXN);
        double rr = ns_since(t0) / (double)total;

        for (size_t i = 0; i < TLB_N; i++) {
            tlb[i].tag = ~0ull;
            tlb[i].addend = 0;
        }
        g_sink = k_rand_tlb(tlb, pt, addend, idx, IDXN, &misses);
        uint64_t m2 = 0;
        t0 = qpc();
        for (int p = 0; p < c.randPasses; p++) {
            g_sink = k_rand_tlb(tlb, pt, addend, idx, IDXN, &misses);
            m2 += misses;
        }
        double rt = ns_since(t0) / (double)total;
        double rmiss = 100.0 * (double)m2 / (double)total;
        L("  %-6s independent direct %6.2f ns | reloc %6.2f ns (x%.2f) | tlb %6.2f ns (x%.2f, miss %.1f%%)", c.name, rd, rr, rr / rd, rt, rt / rd, rmiss);

        if (c.bytes == (256u << 10)) {
            R.reloc_chase_ratio = cr / cd;
            R.tlb_chase_ratio = ct / cd;
            R.reloc_rand_ratio = rr / rd;
            R.tlb_rand_ratio = rt / rd;
        } else if (c.bytes == (8u << 20)) {
            R.tlb_chase_mid = ct / cd;
            R.tlb_rand_mid = rt / rd;
        }
        vfree(arr, 0, MEM_RELEASE);
        vfree(perm, 0, MEM_RELEASE);
    }
    vfree(pt, 0, MEM_RELEASE);
    vfree(tlb, 0, MEM_RELEASE);
    vfree(idx, 0, MEM_RELEASE);
    S("Memory-access cost vs native (cache-resident 256 KB): window base-add x%.2f/x%.2f   inline software TLB x%.2f (dependent) / x%.2f (independent)", R.reloc_chase_ratio, R.reloc_rand_ratio, R.tlb_chase_ratio, R.tlb_rand_ratio);
    S("  same at 8 MB (L3/DRAM-bound, overhead partly hidden): software TLB x%.2f / x%.2f", R.tlb_chase_mid, R.tlb_rand_mid);
}

// ---- indirect branches: native call vs. translated-target hash lookup -------

typedef uint64_t (*ibfn_t)(uint64_t);
template <int N> static NN_NOINLINE uint64_t ibf(uint64_t x) { return x * 0x9E3779B97F4A7C15ull + (uint64_t)N; }
template <size_t... I> static void fill_ib(ibfn_t *t, std::index_sequence<I...>) { ((t[I] = &ibf<(int)I>), ...); }

struct IbtcEnt {
    uint64_t tag, host;
};

static NN_NOINLINE uint64_t k_ind_native(const ibfn_t *t, const uint8_t *seq, size_t n)
{
    uint64_t acc = 1;
    for (size_t i = 0; i < n; i++)
        acc = t[seq[i]](acc);
    return acc;
}

static NN_NOINLINE uint64_t k_ind_ibtc(IbtcEnt *ib, const uint64_t *guest, const ibfn_t *hostfn, const uint8_t *seq, size_t n, uint64_t *miss)
{
    uint64_t acc = 1, m = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t k = seq[i];
        uint64_t ga = guest[k];
        IbtcEnt *e = &ib[(ga >> 2) & 1023];
        if (NN_UNLIKELY(e->tag != ga)) {
            e->tag = ga;
            e->host = (uint64_t)(uintptr_t)hostfn[k];
            m++;
        }
        acc = ((ibfn_t)(uintptr_t)e->host)(acc);
    }
    *miss = m;
    return acc;
}

static void bench_indirect()
{
    L("");
    L("== 6b. Indirect branches: native call vs. translated-target lookup (hash + tag compare + jump) ==");
    static ibfn_t tbl[64];
    fill_ib(tbl, std::make_index_sequence<64>{});
    uint64_t guest[64];
    for (int k = 0; k < 64; k++)
        guest[k] = 0x140001000ull + (uint64_t)k * 0x40;
    static IbtcEnt ib[1024];
    memset(ib, 0xff, sizeof(ib));
    const size_t SN = 1u << 20;
    std::vector<uint8_t> pred(SN), unpred(SN);
    for (size_t i = 0; i < SN; i++) {
        pred[i] = (uint8_t)(i & 3);
        unpred[i] = (uint8_t)(rnd() & 63);
    }
    const int PASSES = 16;
    uint64_t miss = 0;
    double r[4];
    for (int v = 0; v < 2; v++) {
        const std::vector<uint8_t> &seq = v == 0 ? pred : unpred;
        g_sink = k_ind_native(tbl, seq.data(), SN);
        uint64_t t0 = qpc();
        for (int p = 0; p < PASSES; p++)
            g_sink = k_ind_native(tbl, seq.data(), SN);
        r[v * 2] = ns_since(t0) / ((double)SN * PASSES);
        g_sink = k_ind_ibtc(ib, guest, tbl, seq.data(), SN, &miss);
        t0 = qpc();
        for (int p = 0; p < PASSES; p++)
            g_sink = k_ind_ibtc(ib, guest, tbl, seq.data(), SN, &miss);
        r[v * 2 + 1] = ns_since(t0) / ((double)SN * PASSES);
    }
    R.ibtc_pred_ratio = r[1] / r[0];
    R.ibtc_unpred_ratio = r[3] / r[2];
    L("  predictable targets:   native %.2f ns | lookup %.2f ns (x%.2f)", r[0], r[1], R.ibtc_pred_ratio);
    L("  unpredictable targets: native %.2f ns | lookup %.2f ns (x%.2f)", r[2], r[3], R.ibtc_unpred_ratio);
    L("  (lower bound: a real translator also saves flags / builds the guest target first)");
    S("Indirect branch cost, lookup vs native: x%.2f predictable / x%.2f unpredictable", R.ibtc_pred_ratio, R.ibtc_unpred_ratio);
}

// ------------------------------------------------------------ 7. FSGSBASE ----

static void probe_fsgsbase()
{
    L("");
    L("== 7. FSGSBASE: can user mode read the FS/GS base directly? ==");
    JitBuf b;
    PVOID h = nullptr;
    if (!jit_create(b, 4096) || !(h = install_veh())) {
        L("  skipped (needs JIT + vectored exception handlers)");
        jit_destroy(b);
        return;
    }
    static const uint8_t code[] = {
        0xF3, 0x48, 0x0F, 0xAE, 0xC0, 0xC3,                                           // @0  rdfsbase rax ; ret
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                                 // pad
        0xF3, 0x48, 0x0F, 0xAE, 0xC8, 0xC3};                                          // @16 rdgsbase rax ; ret
    memcpy(b.rw, code, sizeof(code));
    FlushInstructionCache(cur(), b.rx, sizeof(code));
    memset(&V, 0, sizeof(V));
    V.stubLo = (uintptr_t)b.rx;
    V.stubHi = V.stubLo + 64;
    V.skipLen = 5;
    V.mode = 4;
    typedef uint64_t (*f64)(void);
    uint64_t fsb = ((f64)(b.rx + 0))();
    LONG udFs = V.stubHit;
    DWORD codeFs = V.stubCode;
    V.stubHit = 0;
    uint64_t gsb = ((f64)(b.rx + 16))();
    LONG udGs = V.stubHit;
    remove_veh(h);
    R.fsgsbase = (udFs == 0 && udGs == 0) ? 1 : 0;
    if (udFs)
        L("  rdfsbase: exception 0x%08lx (instruction not usable)", (unsigned long)codeFs);
    else
        L("  rdfsbase = 0x%llx", (unsigned long long)fsb);
    if (udGs)
        L("  rdgsbase: exception (instruction not usable)");
    else
        L("  rdgsbase = 0x%llx   (TEB = %p)", (unsigned long long)gsb, (void *)NtCurrentTeb());
    S("FSGSBASE usable from user mode: %s", R.fsgsbase == 1 ? "YES (guest FS/GS bases can be swapped cheaply)" : "NO (guest fs:/gs: accesses need explicit base adds)");
    jit_destroy(b);
}

// ---------------------------------------------------------------- gates ------

static void gates()
{
    L("");
    L("== Gates: what these numbers mean for the design ==");
    S("GATE 1 executable memory, dual RW/RX views: %s", R.jit_dualmap ? "PASS" : "FAIL (no code cache possible)");
    S("GATE 2 4 KB views with true aliasing: %s", (R.ph_4k_views && R.ph_alias) ? "PASS" : "FAIL (host-MMU shadow paging impossible; use software TLB)");
    if (R.fault_map_ns > 0) {
        const char *v = R.fault_map_ns < 5000 ? "GOOD (<5 us)" : R.fault_map_ns < 15000 ? "MARGINAL (5-15 us)" : "TOO SLOW (>15 us)";
        S("GATE 3 first-touch fault + map: %.2f us -> %s", R.fault_map_ns / 1000.0, v);
        L("   context: a Windows guest can generate tens of thousands of these per second; at 10 us each, 50k/s costs half a core");
    } else {
        S("GATE 3 first-touch fault + map: no data");
    }
    if (R.total_va_gb >= 0)
        S("GATE 4 address space: %.0f GB reservable in total -> %s", R.total_va_gb, R.total_va_gb >= 4096 ? "room for several large guest windows" : "guest windows must be compact");
    if (R.tlb_rand_ratio > 0) {
        double lo = R.tlb_chase_ratio < R.tlb_rand_ratio ? R.tlb_chase_ratio : R.tlb_rand_ratio;
        double hi = R.tlb_chase_ratio < R.tlb_rand_ratio ? R.tlb_rand_ratio : R.tlb_chase_ratio;
        S("GATE 5 software-TLB fallback: x%.2f..x%.2f per cache-resident memory access vs a native access", lo, hi);
        S("  window base-add costs x%.2f (i.e. nothing measurable) - the cost is the TLB check, not the relocation", R.reloc_rand_ratio);
        S("  if gates 2/3 fail, an unmodified guest pays roughly this on every load/store; ALU-only code pays none of it");
    }
    if (R.ibtc_unpred_ratio > 0)
        S("  indirect branches (calls/returns/virtual dispatch): x%.2f (predictable) .. x%.2f (unpredictable) - the other big per-instruction tax", R.ibtc_pred_ratio, R.ibtc_unpred_ratio);
}

void RunSafeProbes()
{
    resolve_api();
    L("Near-native probe v1 (safe tests)");
    probe_env();
    probe_api_matrix();
    probe_jit();
    PhCtx ctx;
    probe_placeholders(ctx);
    probe_view_scale(ctx);
    probe_faults(ctx);
    probe_va();
    bench_mem();
    bench_indirect();
    probe_fsgsbase();
    gates();
    if (ctx.sec)
        CloseHandle(ctx.sec);
}

// ------------------------------------------- crash-risk tests and their state --
//
// Each test writes "<key>=STARTED" to the state file *before* doing something
// that might terminate the process, and a PASS/FAIL line after. If the process
// dies, the next launch finds STARTED and turns it into DIED - which is the
// answer ("this cannot be recovered from"), not a bug.

static std::wstring g_stateDir;
void SetStateDir(const std::wstring &dir) { g_stateDir = dir; }

typedef std::vector<std::pair<std::string, std::string>> StateVec;

static FILE *wfopen_(const std::wstring &path, const wchar_t *mode)
{
    FILE *f = nullptr;
#if defined(_MSC_VER)
    _wfopen_s(&f, path.c_str(), mode);
#else
    f = _wfopen(path.c_str(), mode);
#endif
    return f;
}

static std::wstring state_path() { return g_stateDir + L"\\nn-probe-state.txt"; }

static StateVec state_load()
{
    StateVec v;
    FILE *f = wfopen_(state_path(), L"r");
    if (!f)
        return v;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        std::string s(line);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        size_t eq = s.find('=');
        if (eq != std::string::npos)
            v.emplace_back(s.substr(0, eq), s.substr(eq + 1));
    }
    fclose(f);
    return v;
}

static void state_save(const StateVec &v)
{
    FILE *f = wfopen_(state_path(), L"w");
    if (!f)
        return;
    for (const auto &kv : v)
        fprintf(f, "%s=%s\n", kv.first.c_str(), kv.second.c_str());
    fflush(f);
    fclose(f);
}

static void state_set(const char *key, const std::string &val)
{
    StateVec v = state_load();
    bool found = false;
    for (auto &kv : v) {
        if (kv.first == key) {
            kv.second = val;
            found = true;
        }
    }
    if (!found)
        v.emplace_back(key, val);
    state_save(v);
}

static std::string state_get(const char *key)
{
    for (const auto &kv : state_load())
        if (kv.first == key)
            return kv.second;
    return std::string();
}

static bool already_done(const char *key)
{
    std::string s = state_get(key);
    return !s.empty() && s.compare(0, 7, "SKIPPED") != 0;
}

static const struct {
    const char *key, *title;
} kTests[] = {
    {"foreign_stack_av", "A1 fault while RSP is on valid non-thread memory"},
    {"compat32", "B  32-bit compatibility mode round trip (CS 0x23 and back)"},
    {"bad_stack_av", "A2 fault while RSP is on an UNMAPPED page"},
};

void ResolveCrashedTests()
{
    StateVec v = state_load();
    bool changed = false;
    for (auto &kv : v) {
        if (kv.second == "STARTED") {
            kv.second = "DIED: the process was terminated during this test";
            changed = true;
            L("(previous run: test '%s' was terminated by the OS)", kv.first.c_str());
        }
    }
    if (changed)
        state_save(v);
}

void ReportDangerousState()
{
    L("");
    L("== Crash-risk test results (persisted across launches) ==");
    for (const auto &t : kTests) {
        std::string s = state_get(t.key);
        S("%s: %s", t.title, s.empty() ? "not run" : s.c_str());
    }
}

// Low (below 2 GB) RX + RW views of one section: 32-bit code needs 32-bit addresses.
static bool jit_create_low(JitBuf &b, SIZE_T size)
{
    b.size = size;
    b.sec = create_section(size, PAGE_EXECUTE_READWRITE, &b.api);
    if (!b.sec) {
        L("  section create failed, err %lu", (unsigned long)GetLastError());
        return false;
    }
    if (!(g.MapViewOfFile3FromApp || g.MapViewOfFile3)) {
        L("  MapViewOfFile3* missing: cannot place views at fixed low addresses");
        return false;
    }
    static const uintptr_t cands[] = {0x30000000, 0x38000000, 0x40000000, 0x48000000, 0x50000000, 0x58000000, 0x60000000, 0x68000000, 0x20000000, 0x28000000, 0x18000000, 0x10000000};
    for (uintptr_t c : cands) {
        void *rx = map3(b.sec, (void *)c, 0, size, 0, PAGE_EXECUTE_READ);
        if (!rx)
            continue;
        void *rw = map3(b.sec, (void *)(c + 0x1000000), 0, size, 0, PAGE_READWRITE);
        if (!rw) {
            if (g.UnmapViewOfFile_)
                g.UnmapViewOfFile_(rx);
            continue;
        }
        b.rx = (uint8_t *)rx;
        b.rw = (uint8_t *)rw;
        return true;
    }
    L("  no free low address range found among the candidates");
    return false;
}

static void test_foreign_stack()
{
    L("");
    L("-- A1: access violation while RSP points at valid RW memory that is NOT the thread stack --");
    L("   (a translator that runs guest code on guest stacks needs this to be deliverable)");
    JitBuf b;
    PVOID h = nullptr;
    uint8_t *stk = nullptr;
    if (!jit_create(b, 4096) || !(h = install_veh()) || !(stk = (uint8_t *)valloc(65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
        state_set("foreign_stack_av", "SKIPPED: needs JIT, vectored handlers and 64 KB of RW memory");
        L("  skipped");
        remove_veh(h);
        jit_destroy(b);
        return;
    }
    static const uint8_t code[] = {
        0x48, 0x89, 0xE0, // mov rax, rsp
        0x48, 0x89, 0xCC, // mov rsp, rcx
        0x31, 0xD2,       // xor edx, edx
        0x48, 0x8B, 0x12, // mov rdx, [rdx]   <- faults (NULL)
        0x48, 0x89, 0xC4, // mov rsp, rax
        0xC3};            // ret
    memcpy(b.rw, code, sizeof(code));
    FlushInstructionCache(cur(), b.rx, sizeof(code));
    memset(&V, 0, sizeof(V));
    V.stubLo = (uintptr_t)b.rx;
    V.stubHi = V.stubLo + sizeof(code);
    V.recoverRip = V.stubLo + 14;
    V.mode = 4;
    state_set("foreign_stack_av", "STARTED");
    typedef uint64_t (*fcall)(uint64_t);
    ((fcall)b.rx)((uint64_t)(uintptr_t)(stk + 0xF000));
    V.mode = 0;
    char msg[256];
    if (V.stubHit == 1) {
        snprintf(msg, sizeof(msg), "PASS: handler ran (exception 0x%08lx, RSP at fault %p, inside thread stack bounds: %s)", (unsigned long)V.stubCode, (void *)V.stubRsp, V.rspInStack ? "yes" : "no");
    } else {
        snprintf(msg, sizeof(msg), "FAIL: stub returned without the handler running (hit count %ld)", (long)V.stubHit);
    }
    state_set("foreign_stack_av", msg);
    L("  %s", msg);
    remove_veh(h);
    vfree(stk, 0, MEM_RELEASE);
    jit_destroy(b);
}

static void test_compat32()
{
    L("");
    L("-- B: far return into 32-bit compatibility mode (CS=0x23) and back (needed for any 32-bit game) --");
    JitBuf b;
    PVOID h = nullptr;
    if (!jit_create_low(b, 0x10000) || !(h = install_veh())) {
        state_set("compat32", "SKIPPED: needs low (<2 GB) executable views and vectored handlers");
        L("  skipped");
        remove_veh(h);
        jit_destroy(b);
        return;
    }
    uint32_t rx32 = (uint32_t)(uintptr_t)b.rx;
    uint32_t c32 = rx32 + 0x100, l64 = rx32 + 0x200;
    L("  low RX view at 0x%08x, RW view at %p", (unsigned)rx32, (void *)b.rw);
    uint8_t code[0x210];
    memset(code, 0xCC, sizeof(code));
    auto put = [&](size_t off, std::initializer_list<uint8_t> bytes) {
        size_t i = off;
        for (uint8_t x : bytes)
            code[i++] = x;
    };
    // entry64 @0x000 : push rbx; mov rbx,rsp; mov rsp,rcx; push 0x23; push c32; retfq
    put(0x000, {0x53, 0x48, 0x89, 0xE3, 0x48, 0x89, 0xCC, 0x6A, 0x23, 0x68, (uint8_t)c32, (uint8_t)(c32 >> 8), (uint8_t)(c32 >> 16), (uint8_t)(c32 >> 24), 0x48, 0xCB});
    // compat32 @0x100: mov eax,0x12345678; push 0x33; push l64; retf
    put(0x100, {0xB8, 0x78, 0x56, 0x34, 0x12, 0x6A, 0x33, 0x68, (uint8_t)l64, (uint8_t)(l64 >> 8), (uint8_t)(l64 >> 16), (uint8_t)(l64 >> 24), 0xCB});
    // landing64 @0x200: mov rsp,rbx; pop rbx; ret
    put(0x200, {0x48, 0x89, 0xDC, 0x5B, 0xC3});
    memcpy(b.rw, code, sizeof(code));
    FlushInstructionCache(cur(), b.rx, sizeof(code));
    memset(&V, 0, sizeof(V));
    V.stubLo = (uintptr_t)b.rx;
    V.stubHi = V.stubLo + 0x300;
    V.recoverRip = (uintptr_t)l64 + 3; // the 'pop rbx' after 'mov rsp,rbx'
    V.mode = 5;
    state_set("compat32", "STARTED");
    typedef uint32_t (*entry_t)(uint64_t);
    uint32_t r = ((entry_t)b.rx)((uint64_t)(uintptr_t)(b.rw + 0xF000));
    V.mode = 0;
    char msg[256];
    if (V.stubHit == 0 && r == 0x12345678u)
        snprintf(msg, sizeof(msg), "PASS: 32-bit code ran natively and returned 0x%08x", (unsigned)r);
    else
        snprintf(msg, sizeof(msg), "FAIL: exception 0x%08lx (%ld hits), result 0x%08x - compatibility mode not usable from this process", (unsigned long)V.stubCode, (long)V.stubHit, (unsigned)r);
    state_set("compat32", msg);
    L("  %s", msg);
    remove_veh(h);
    jit_destroy(b);
}

static void test_bad_stack()
{
    L("");
    L("-- A2: access violation while RSP points at an UNMAPPED page --");
    L("   (predicted: the OS cannot build the exception frame and kills the process; relaunch the app to see the verdict)");
    JitBuf b;
    PVOID h = nullptr;
    uint8_t *bad = nullptr;
    if (!jit_create(b, 4096) || !(h = install_veh()) || !(bad = (uint8_t *)valloc(1 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS))) {
        state_set("bad_stack_av", "SKIPPED: needs JIT, vectored handlers and a NOACCESS region");
        L("  skipped");
        remove_veh(h);
        jit_destroy(b);
        return;
    }
    static const uint8_t code[] = {
        0x48, 0x89, 0xE0, // mov rax, rsp
        0x48, 0x89, 0xCC, // mov rsp, rcx
        0x50,             // push rax        <- faults: [rsp-8] is PAGE_NOACCESS
        0x48, 0x89, 0xC4, // mov rsp, rax
        0xC3};            // ret
    memcpy(b.rw, code, sizeof(code));
    FlushInstructionCache(cur(), b.rx, sizeof(code));
    memset(&V, 0, sizeof(V));
    V.stubLo = (uintptr_t)b.rx;
    V.stubHi = V.stubLo + sizeof(code);
    V.recoverRip = V.stubLo + 10;
    V.mode = 4;
    state_set("bad_stack_av", "STARTED");
    typedef uint64_t (*fcall)(uint64_t);
    ((fcall)b.rx)((uint64_t)(uintptr_t)(bad + 0x80000));
    V.mode = 0;
    char msg[256];
    if (V.stubHit == 1)
        snprintf(msg, sizeof(msg), "SURVIVED: handler ran (exception 0x%08lx, RSP at fault %p) - faults on unmapped guest stacks ARE deliverable", (unsigned long)V.stubCode, (void *)V.stubRsp);
    else
        snprintf(msg, sizeof(msg), "FAIL: stub returned without the handler running (hit count %ld)", (long)V.stubHit);
    state_set("bad_stack_av", msg);
    L("  %s", msg);
    remove_veh(h);
    vfree(bad, 0, MEM_RELEASE);
    jit_destroy(b);
}

void RunDangerous()
{
    resolve_api();
    L("Near-native probe v1 (crash-risk tests)");
    // Least likely to kill the process first, so one launch yields as much as possible.
    if (!already_done("foreign_stack_av"))
        test_foreign_stack();
    if (!already_done("compat32"))
        test_compat32();
    if (!already_done("bad_stack_av"))
        test_bad_stack();
}

} // namespace nn
