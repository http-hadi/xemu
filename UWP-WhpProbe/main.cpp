// WHP probe for UWP / Xbox Developer Mode.
//
// Answers one question: can a UWP app on this device use the Windows
// Hypervisor Platform (WinHvPlatform.dll)? It checks, in order:
//   1. what the CPU / hypervisor expose through plain CPUID
//   2. whether the WHP DLLs are visible and loadable from the app sandbox
//   3. whether WHvGetCapability(HypervisorPresent) says yes
//   4. whether a partition + vCPU can be created and actually run guest code
//
// The full report is written to LocalState\whp-probe.txt (flushed line by
// line, so a hang still leaves partial results) and a summary is shown in a
// message dialog.

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <string>
#include <vector>
#include <thread>

using namespace Platform;
using namespace Windows::ApplicationModel::Core;
using namespace Windows::UI::Core;
using namespace Windows::UI::Popups;
using namespace Windows::Storage;

extern "C" WINBASEAPI BOOL WINAPI GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE *phModule);

// ---------------------------------------------------------------- logging --

static FILE *g_log = nullptr;
static std::vector<std::string> g_summary;

static std::string vfmt(const char *fmt, va_list ap)
{
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    buf[sizeof(buf) - 1] = 0;
    return std::string(buf);
}

static void emit(const std::string &s)
{
    if (g_log) {
        fputs(s.c_str(), g_log);
        fputc('\n', g_log);
        fflush(g_log);
    }
}

// L: report only.  S: report + shown in the on-screen summary.
static void L(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::string s = vfmt(fmt, ap);
    va_end(ap);
    emit(s);
}

static void S(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::string s = vfmt(fmt, ap);
    va_end(ap);
    g_summary.push_back(s);
    emit(s);
}

// -------------------------------------------------------- environment info --

static void probe_os()
{
    HMODULE nt = nullptr;
    if (GetModuleHandleExW(0, L"ntdll.dll", &nt) && nt) {
        typedef LONG(WINAPI * RtlGetVersion_t)(OSVERSIONINFOW *);
        RtlGetVersion_t fn = (RtlGetVersion_t)GetProcAddress(nt, "RtlGetVersion");
        if (fn) {
            OSVERSIONINFOW vi = {};
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (fn(&vi) == 0) {
                S("OS build: %lu.%lu.%lu", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
                return;
            }
        }
    }
    L("OS build: unavailable");
}

static void probe_cpu()
{
    int r[4];

    __cpuid(r, 0);
    char vendor[13];
    memcpy(vendor + 0, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    vendor[12] = 0;

    __cpuid(r, 0x80000000);
    unsigned maxExt = (unsigned)r[0];
    char brand[49] = {};
    if (maxExt >= 0x80000004) {
        for (int i = 0; i < 3; i++) {
            __cpuid(r, 0x80000002 + i);
            memcpy(brand + 16 * i, r, 16);
        }
    }
    L("CPU vendor: %s", vendor);
    L("CPU brand : %s", brand);

    __cpuid(r, 1);
    bool hvbit = ((unsigned)r[2] >> 31) & 1;
    bool vmx = ((unsigned)r[2] >> 5) & 1;
    bool svm = false;
    if (maxExt >= 0x80000001) {
        __cpuid(r, 0x80000001);
        svm = ((unsigned)r[2] >> 2) & 1;
    }

    S("CPUID: running under a hypervisor: %s", hvbit ? "yes" : "no");
    S("CPUID: virtualization extensions visible to us: SVM=%s VMX=%s", svm ? "yes" : "no", vmx ? "yes" : "no");

    if (hvbit) {
        __cpuid(r, 0x40000000);
        unsigned maxHv = (unsigned)r[0];
        char hv[13];
        memcpy(hv + 0, &r[1], 4);
        memcpy(hv + 4, &r[2], 4);
        memcpy(hv + 8, &r[3], 4);
        hv[12] = 0;
        L("Hypervisor vendor: '%s', max leaf 0x%x", hv, maxHv);
        for (unsigned leaf = 0x40000001; leaf <= maxHv && leaf <= 0x4000000A; leaf++) {
            __cpuid(r, (int)leaf);
            L("  leaf 0x%08x: eax=%08x ebx=%08x ecx=%08x edx=%08x", leaf, (unsigned)r[0], (unsigned)r[1],
              (unsigned)r[2], (unsigned)r[3]);
        }
    }
    if (svm) {
        __cpuid(r, 0x8000000A);
        L("SVM leaf 0x8000000A: eax=%08x ebx=%08x ecx=%08x edx=%08x", (unsigned)r[0], (unsigned)r[1],
          (unsigned)r[2], (unsigned)r[3]);
    }
}

static void check_file(const wchar_t *path)
{
    WIN32_FILE_ATTRIBUTE_DATA d = {};
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &d)) {
        unsigned long long sz = ((unsigned long long)d.nFileSizeHigh << 32) | d.nFileSizeLow;
        L("  %ls: readable, %llu bytes", path, sz);
    } else {
        L("  %ls: not accessible (err %lu)", path, GetLastError());
    }
}

// ------------------------------------------------------------ WHP plumbing --

typedef HMODULE(WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);

typedef HRESULT(WINAPI *fnGetCap)(UINT32, void *, UINT32, UINT32 *);
typedef HRESULT(WINAPI *fnCreatePartition)(void **);
typedef HRESULT(WINAPI *fnSetupPartition)(void *);
typedef HRESULT(WINAPI *fnDeletePartition)(void *);
typedef HRESULT(WINAPI *fnSetProp)(void *, UINT32, const void *, UINT32);
typedef HRESULT(WINAPI *fnMapGpa)(void *, void *, UINT64, UINT64, UINT32);
typedef HRESULT(WINAPI *fnCreateVp)(void *, UINT32, UINT32);
typedef HRESULT(WINAPI *fnDeleteVp)(void *, UINT32);
typedef HRESULT(WINAPI *fnRunVp)(void *, UINT32, void *, UINT32);
typedef HRESULT(WINAPI *fnSetRegs)(void *, UINT32, const UINT32 *, UINT32, const void *);

struct RegVal {
    alignas(16) UINT64 q[2];
};

// Loads a system DLL from inside the UWP sandbox. LoadLibraryExW is not part
// of the UWP API surface, so it is resolved at runtime from kernelbase.
static HMODULE load_system_dll(const wchar_t *name)
{
    HMODULE kb = nullptr;
    GetModuleHandleExW(0, L"kernelbase.dll", &kb);
    LoadLibraryExW_t ll = kb ? (LoadLibraryExW_t)GetProcAddress(kb, "LoadLibraryExW") : nullptr;
    if (!ll) {
        L("  kernelbase!LoadLibraryExW could not be resolved (err %lu)", GetLastError());
        return nullptr;
    }

    std::wstring full = L"C:\\Windows\\System32\\";
    full += name;

    struct Try {
        const wchar_t *path;
        DWORD flags;
    } tries[] = {
        {name, 0},
        {name, 0x00000800 /* LOAD_LIBRARY_SEARCH_SYSTEM32 */},
        {full.c_str(), 0},
    };
    for (const Try &t : tries) {
        SetLastError(0);
        HMODULE h = ll(t.path, nullptr, t.flags);
        DWORD e = GetLastError();
        L("  LoadLibraryExW(%ls, flags=0x%x) -> %p (err %lu)", t.path, (unsigned)t.flags, (void *)h, e);
        if (h)
            return h;
    }
    return nullptr;
}

static const char *exit_name(UINT32 r)
{
    switch (r) {
    case 0x0: return "None";
    case 0x1: return "MemoryAccess";
    case 0x2: return "X64IoPortAccess";
    case 0x4: return "UnrecoverableException";
    case 0x5: return "InvalidVpRegisterValue";
    case 0x6: return "UnsupportedFeature";
    case 0x7: return "X64InterruptWindow";
    case 0x8: return "X64Halt";
    case 0x9: return "X64ApicEoi";
    case 0x1000: return "X64MsrAccess";
    case 0x1001: return "X64Cpuid";
    case 0x1002: return "Exception";
    case 0x2001: return "Canceled";
    default: return "?";
    }
}

static void dump_hex(const char *tag, const unsigned char *p, size_t n)
{
    std::string s = tag;
    char b[8];
    for (size_t i = 0; i < n; i++) {
        snprintf(b, sizeof(b), "%02x", p[i]);
        if (i % 16 == 0)
            s += "\n    ";
        s += b;
        s += " ";
    }
    emit(s);
}

// Returns the one-line verdict.
static std::string probe_whp()
{
    L("");
    L("== WHP DLL availability ==");
    check_file(L"C:\\Windows\\System32\\WinHvPlatform.dll");
    check_file(L"C:\\Windows\\System32\\WinHvEmulation.dll");
    check_file(L"C:\\Windows\\System32\\vid.dll");
    check_file(L"C:\\Windows\\System32\\drivers\\winhvr.sys");
    check_file(L"C:\\Windows\\System32\\drivers\\vid.sys");

    L("");
    L("== Loading WinHvPlatform.dll ==");
    HMODULE whp = load_system_dll(L"WinHvPlatform.dll");
    if (!whp) {
        S("WinHvPlatform.dll: cannot be loaded from this app");
        return "BLOCKED: WinHvPlatform.dll cannot be loaded from the UWP sandbox";
    }
    S("WinHvPlatform.dll: loaded");

    L("");
    L("== Loading WinHvEmulation.dll (needed for MMIO emulation) ==");
    HMODULE emu = load_system_dll(L"WinHvEmulation.dll");
    S("WinHvEmulation.dll: %s", emu ? "loaded" : "cannot be loaded");

    fnGetCap pGetCap = (fnGetCap)GetProcAddress(whp, "WHvGetCapability");
    fnCreatePartition pCreate = (fnCreatePartition)GetProcAddress(whp, "WHvCreatePartition");
    fnSetupPartition pSetup = (fnSetupPartition)GetProcAddress(whp, "WHvSetupPartition");
    fnDeletePartition pDelete = (fnDeletePartition)GetProcAddress(whp, "WHvDeletePartition");
    fnSetProp pSetProp = (fnSetProp)GetProcAddress(whp, "WHvSetPartitionProperty");
    fnMapGpa pMap = (fnMapGpa)GetProcAddress(whp, "WHvMapGpaRange");
    fnCreateVp pCreateVp = (fnCreateVp)GetProcAddress(whp, "WHvCreateVirtualProcessor");
    fnDeleteVp pDeleteVp = (fnDeleteVp)GetProcAddress(whp, "WHvDeleteVirtualProcessor");
    fnRunVp pRun = (fnRunVp)GetProcAddress(whp, "WHvRunVirtualProcessor");
    fnSetRegs pSetRegs = (fnSetRegs)GetProcAddress(whp, "WHvSetVirtualProcessorRegisters");

    L("exports: GetCapability=%p CreatePartition=%p SetupPartition=%p SetPartitionProperty=%p MapGpaRange=%p",
      (void *)pGetCap, (void *)pCreate, (void *)pSetup, (void *)pSetProp, (void *)pMap);
    L("exports: CreateVirtualProcessor=%p RunVirtualProcessor=%p SetVirtualProcessorRegisters=%p",
      (void *)pCreateVp, (void *)pRun, (void *)pSetRegs);

    if (!pGetCap || !pCreate || !pSetup || !pSetProp || !pMap || !pCreateVp || !pRun || !pSetRegs) {
        S("WHP exports: some entry points are missing");
        return "BLOCKED: WinHvPlatform.dll loaded but entry points are missing";
    }

    L("");
    L("== Capabilities ==");
    BOOL present = FALSE;
    UINT32 written = 0;
    HRESULT hr = pGetCap(0 /* HypervisorPresent */, &present, sizeof(present), &written);
    S("WHvGetCapability(HypervisorPresent): hr=0x%08lx value=%d", (unsigned long)hr, (int)present);

    UINT64 caps = 0;
    hr = pGetCap(1 /* Features */, &caps, sizeof(caps), &written);
    L("WHvGetCapability(Features): hr=0x%08lx value=0x%llx", (unsigned long)hr, (unsigned long long)caps);
    caps = 0;
    hr = pGetCap(2 /* ExtendedVmExits */, &caps, sizeof(caps), &written);
    L("WHvGetCapability(ExtendedVmExits): hr=0x%08lx value=0x%llx", (unsigned long)hr, (unsigned long long)caps);
    UINT32 vendor = 0;
    hr = pGetCap(0x1000 /* ProcessorVendor */, &vendor, sizeof(vendor), &written);
    L("WHvGetCapability(ProcessorVendor): hr=0x%08lx value=%u", (unsigned long)hr, (unsigned)vendor);

    L("");
    L("== Partition + vCPU + guest execution ==");
    void *part = nullptr;
    hr = pCreate(&part);
    S("WHvCreatePartition: hr=0x%08lx", (unsigned long)hr);
    if (FAILED(hr))
        return present ? "BLOCKED: hypervisor reported present but a partition cannot be created"
                       : "BLOCKED: no hypervisor available to this app (HypervisorPresent=0)";

    std::string verdict = "FAILED: see report";

    UINT32 cpus = 1;
    hr = pSetProp(part, 0x1fff /* ProcessorCount */, &cpus, sizeof(cpus));
    L("WHvSetPartitionProperty(ProcessorCount=1): hr=0x%08lx", (unsigned long)hr);

    hr = pSetup(part);
    S("WHvSetupPartition: hr=0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) {
        if (pDelete)
            pDelete(part);
        return "BLOCKED: partition created but setup failed";
    }

    // Guest code at GPA 0x1000 (real mode, CS base 0):
    //   mov al, 0x42 ; out 0x80, al ; hlt
    void *mem = VirtualAllocFromApp(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        L("VirtualAllocFromApp failed (err %lu)", GetLastError());
        pDelete(part);
        return "FAILED: could not allocate guest memory";
    }
    memset(mem, 0xF4, 0x1000);
    const unsigned char stub[] = {0xB0, 0x42, 0xE6, 0x80, 0xF4};
    memcpy(mem, stub, sizeof(stub));

    hr = pMap(part, mem, 0x1000, 0x1000, 7 /* R|W|X */);
    S("WHvMapGpaRange: hr=0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) {
        pDelete(part);
        return "BLOCKED: guest memory could not be mapped";
    }

    hr = pCreateVp(part, 0, 0);
    S("WHvCreateVirtualProcessor: hr=0x%08lx", (unsigned long)hr);
    if (FAILED(hr)) {
        pDelete(part);
        return "BLOCKED: virtual processor could not be created";
    }

    {
        UINT32 names[2] = {0x13 /* Cs */, 0x10 /* Rip */};
        RegVal vals[2] = {};
        vals[0].q[0] = 0;                                                  // base
        vals[0].q[1] = (UINT64)0xFFFF | ((UINT64)0 << 32) | ((UINT64)0x9B << 48); // limit | selector | attributes
        vals[1].q[0] = 0x1000;
        hr = pSetRegs(part, 0, names, 2, vals);
        L("WHvSetVirtualProcessorRegisters(CS,RIP): hr=0x%08lx", (unsigned long)hr);
    }

    bool sawIo = false, sawHalt = false;
    alignas(16) unsigned char ctx[512];
    for (int i = 0; i < 6 && !sawHalt; i++) {
        memset(ctx, 0, sizeof(ctx));
        hr = pRun(part, 0, ctx, sizeof(ctx));
        if (FAILED(hr)) {
            S("WHvRunVirtualProcessor #%d: hr=0x%08lx", i, (unsigned long)hr);
            break;
        }
        UINT32 reason = *(UINT32 *)ctx;
        L("  run #%d: exit reason 0x%x (%s)", i, (unsigned)reason, exit_name(reason));
        if (reason == 0x2) {
            UINT16 port = *(UINT16 *)(ctx + 72);
            UINT64 rax = *(UINT64 *)(ctx + 80);
            L("    I/O exit: port=0x%x rax=0x%llx", (unsigned)port, (unsigned long long)rax);
            if (port == 0x80 && (rax & 0xff) == 0x42)
                sawIo = true;
            UINT64 rip = *(UINT64 *)(ctx + 32);
            unsigned len = ctx[10] & 0xF;
            if (!len)
                len = 2;
            UINT32 name = 0x10; // Rip
            RegVal v = {};
            v.q[0] = rip + len;
            hr = pSetRegs(part, 0, &name, 1, &v);
            L("    advance RIP by %u: hr=0x%08lx", len, (unsigned long)hr);
        } else if (reason == 0x8) {
            sawHalt = true;
        } else {
            dump_hex("    exit context:", ctx, 96);
            break;
        }
    }
    S("Guest executed: I/O exit seen=%s, HLT exit seen=%s", sawIo ? "yes" : "no", sawHalt ? "yes" : "no");

    if (sawIo && sawHalt)
        verdict = "PASS: hardware virtualization works from this app";
    else
        verdict = "FAILED: partition runs but guest execution did not behave as expected";

    if (pDeleteVp)
        pDeleteVp(part, 0);
    if (pDelete)
        pDelete(part);
    return verdict;
}

// ------------------------------------------------------------------ driver --

static std::string RunProbe(const std::wstring &dir)
{
    std::wstring path = dir + L"\\whp-probe.txt";
    _wfopen_s(&g_log, path.c_str(), L"w");

    L("WHP probe v1");
    L("Report file: %ls", path.c_str());
    L("");
    L("== Environment ==");
    probe_os();
    probe_cpu();

    std::string verdict = probe_whp();

    L("");
    L("VERDICT: %s", verdict.c_str());
    if (g_log) {
        fclose(g_log);
        g_log = nullptr;
    }

    std::string text = "VERDICT: " + verdict + "\n\n";
    for (const std::string &s : g_summary)
        text += s + "\n";
    text += "\nFull report: ";
    text += std::string(path.begin(), path.end());
    return text;
}

namespace WhpProbe
{
ref class App sealed : public IFrameworkViewSource, public IFrameworkView
{
public:
    virtual IFrameworkView ^ CreateView() { return this; }
    virtual void Initialize(CoreApplicationView ^) {}
    virtual void SetWindow(CoreWindow ^) {}
    virtual void Load(String ^) {}
    virtual void Uninitialize() {}
    virtual void Run()
    {
        CoreWindow ^window = CoreWindow::GetForCurrentThread();
        window->Activate();
        std::wstring dir = ApplicationData::Current->LocalFolder->Path->Data();
        std::thread([window, dir]() {
            std::string text = RunProbe(dir);
            std::wstring wide(text.begin(), text.end());
            String ^msg = ref new String(wide.c_str());
            window->Dispatcher->RunAsync(CoreDispatcherPriority::Normal, ref new DispatchedHandler([msg]() {
                MessageDialog ^dlg = ref new MessageDialog(msg, "WHP probe");
                dlg->ShowAsync();
            }));
        }).detach();
        window->Dispatcher->ProcessEvents(CoreProcessEventsOption::ProcessUntilQuit);
    }
};
} // namespace WhpProbe

[Platform::MTAThread] int main(Platform::Array<Platform::String ^> ^)
{
    CoreApplication::Run(ref new WhpProbe::App());
    return 0;
}
