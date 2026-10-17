# Near-native plan: what is real, what is gated

Context: Xbox Series X in Dev Mode, UWP only, no hypervisor access (WHPX is not available; see the
`whp-probe` branch), JIT allowed through the `codeGeneration` capability (dual RW/RX section views).
The CPU is x86-64, so guest *user-mode* code can in principle run on the host CPU natively.

## Four tracks

| Track | What it is | Realistic outcome | Status |
|---|---|---|---|
| A. Tune TCG | Fix overheads in the current QEMU host (display path, Debug builds, `qemu64` + IDE/e1000/USB-tablet presets, tiny code cache) | Windows 10 goes from "very slow" to "usable"; still ~an order of magnitude below native | Cheap; independent of everything below |
| B. Same-ISA translator as a QEMU accelerator | Copy-and-patch translation of guest code, QEMU's devices/firmware/softmmu reused, TCG as fallback | If host-MMU shadow paging works: much better. If not: software TLB, roughly 2-4x slower than native for unmodified Windows | **Gated on this probe** |
| C. Native user-mode loader (Wine-style) | No guest kernel: PE loader + Win32/NT layer + D3D forwarding. Guest code *is* host code | Native CPU and native D3D (FL 11.0 cap). The only track where "run PC games at full speed" holds | Already started in `xbox-win32-runner` |
| D. Paravirtual Linux guest | Linux built as a library for the translator's runtime; compact address space; 64 KB-granular memory | The only whole-OS guest where near-native numbers can hold | Needs B's engine first |

## About switching to a Linux guest

Linux does **not** speed anything up today: under TCG the CPU path is identical. What it changes:

* **GPU:** Mesa already ships guest drivers for virtio-gpu (virgl) and Venus (Vulkan). A Windows guest
  needs a custom WDDM driver. The UWP port in this fork already carries Mesa Dozen (Vulkan on D3D12),
  so a Venus -> host Vulkan (Dozen) -> D3D12 chain is conceivable. Unproven; the hard part is the host
  memory-sharing model (blob resources / host-visible memory) on UWP.
* **Kernel control:** only an open kernel can be built as a library for the translator's runtime, which
  removes ring/IDT/CR3 emulation and lets memory be managed in 64 KB units (what Windows' view
  granularity wanted). Windows can never get that.
* **Games:** native Linux titles, or Windows titles through Proton/DXVK (Vulkan). Proton adds a layer
  on top of an emulated CPU, so until B exists expect no gain over Windows-in-TCG.

## Hazards in the translator design, mapped to the probe

| Hazard | Probe |
|---|---|
| 47-bit user VA cannot hold a 48-bit guest; Windows/Linux ASLR scatters allocations | 5 |
| Guest page = 4 KB, Windows view = 64 KB unless placeholders relax it | 3 |
| Each guest PTE change is a host syscall; each first touch is an exception round trip | 3, 4 |
| Windows delivers user exceptions on the faulting stack (no alternate stack) | A1, A2 |
| "Copy bytes as-is" breaks for relocated memory operands, RIP-relative, branches, `gs:`/`fs:` | 6a, 7 |
| Indirect branches / returns need a lookup | 6b |
| Guest JIT code wants RWX; the host offers RW/RX views or RW<->RX toggling | 2 |
| 32-bit guests need compatibility mode | B |

## Not implemented here (on purpose)

The translator, the paravirtual GPU and the Linux guest kernel are **not** in this branch. Each of
them would be a multi-month project whose shape depends on the numbers above (host-MMU vs
software TLB; whether stacks can be foreign; whether 32-bit works). Build them after the probe.

Suggested order once numbers are in: (1) differential-test harness against TCG, (2) translator for
user-mode code only, with QEMU's softmmu TLB layout and `helper_*` calls for sensitive instructions,
(3) kernel mode, (4) paravirtual devices, (5) GPU.
