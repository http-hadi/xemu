# Near-native probe

Branch `nn-probe` holds one self-contained UWP app, **UWP-NearNativeProbe**, built by
`.github/workflows/nn-probe.yml`. It does not emulate anything. It *measures*, on the real
console, the unknowns that decide whether a same-ISA, near-native whole-OS translator
(see [docs/NEAR_NATIVE_PLAN.md](docs/NEAR_NATIVE_PLAN.md)) can work inside a UWP app.

It follows the same pattern as the `whp-probe` branch: CI builds a sideloadable MSIX, publishes
it as a prerelease, and pushes build logs to `ci-logs/nn-probe/`.

## Running it on the console

1. GitHub -> **Releases** -> newest `nn-probe-runN` (prerelease). Download the `.msix`, the `.cer`
   and the VCLibs `.appx` from `Dependencies`.
2. Sideload through Device Portal (install the VCLibs `.appx` first if it is not already installed).
3. **Switch the app's type from App to Game** (Dev Home / Device Portal). Apps share 2-4 cores and a
   slice of the GPU; games get 4 exclusive + 2 shared cores. Numbers taken as an "App" are not
   representative of what a translator would get.
4. Launch *Near-native Probe*. The safe tests take roughly 1-2 minutes, then a dialog shows a summary.
5. Choose **Done**, or **Run crash-risk tests (app may close)**. If the app closes during those, that
   is a result, not a bug: relaunch it and the verdict is recovered from the state file.
6. Device Portal -> File Explorer -> LocalAppData -> *Near-native Probe* -> LocalState. Download
   `nn-probe.txt` and `nn-probe-state.txt` and send them back.

Everything is flushed line by line, so a hang or crash still leaves a partial report.

## What each section measures

| Section | Question it answers | Why it matters |
|---|---|---|
| 0 Environment | What CPU/hypervisor/VA range/core count does the app really see? | Picks `-cpu`, sizes windows, shows App-vs-Game resources |
| 1 API matrix | Which of the memory/exception/NT APIs exist in the sandbox? | A missing API is a design constraint, not a bug |
| 2 Executable memory | Dual RW/RX views? RWX alloc? RW->RX toggle? icache flush cost? | Code cache design; how guest JIT code (browsers, .NET, Java) must be handled |
| 3 4 KB views | Can one physical page be mapped at 4 KB granularity, at non-64 KB base and offset, with true aliasing? | The load-bearing wall of "host MMU does the guest MMU's job" |
| 3b View scaling | How many separate 4 KB views can a process hold? | Each view is its own VAD |
| 4 Fault round trips | Cost of AV + fix-up, AV + map, bare software exception | Shadow paging pays this on every first touch |
| 5 VA limits | Largest reservation / total reservable VA | Size of guest "windows" |
| 6a Translation cost | Same loop with native / base-add / inline software-TLB addressing | What a translator pays per load/store on this CPU |
| 6b Indirect branches | Native call vs hash-lookup-and-jump | Calls/returns/virtual dispatch are the other big tax |
| 7 FSGSBASE | Can user mode read (and so swap) FS/GS base? | Guest TEB/TLS (`gs:`/`fs:`) handling |
| Crash-risk A1 | Is a fault deliverable when RSP is on valid non-thread memory? | Running guest code on guest stacks |
| Crash-risk A2 | ...when RSP is on an *unmapped* page? | Lazy mapping of guest stacks (Windows has no alternate exception stack) |
| Crash-risk B | Can the process enter and leave 32-bit compatibility mode (CS 0x23)? | Any 32-bit game, and WoW64-style loaders |

## Decision gates

The report ends with automatic GATE lines. Rough reading:

* **Gate 2 fails** (no 4 KB aliasing) -> host-MMU shadow paging is impossible; an unmodified guest needs the software-TLB path (Gate 5 gives its per-access cost).
* **Gate 3 > ~15 us** -> lazy shadow paging burns cores on a Windows guest; software TLB again.
* **Gate 1 fails** -> no code cache; nothing in the plan works.
* **A2 = DIED** -> guest stacks must never be the host stack; push/pop/call/ret get translated, not copied.
* **B = PASS** -> 32-bit guests/loaders are possible natively.

## Local harness

`tools/run-local-harness.sh` builds `probes.cpp` as a console program (MinGW) and runs it under Wine.
It validates the probe *logic* (JIT stubs, exception handling, the crash-risk state machine). It says
nothing about the console.
