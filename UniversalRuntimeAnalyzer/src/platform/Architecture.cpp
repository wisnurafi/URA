// platform/Architecture.cpp
#include "Architecture.hpp"

#include <atomic>

namespace ura::platform {

    namespace {
        // IMAGE_FILE_MACHINE_* constants we care about. Numbers come from
        // <winnt.h>. Hard-coded here so the runtime resolution path doesn't
        // need any extra SDK pieces.
        constexpr USHORT kMachineUnknown = 0x0000;
        constexpr USHORT kMachineI386    = 0x014C;
        constexpr USHORT kMachineAMD64   = 0x8664;
        constexpr USHORT kMachineARM     = 0x01C4;
        constexpr USHORT kMachineARM64   = 0xAA64;

        core::Architecture from_machine(USHORT m) noexcept {
            switch (m) {
                case kMachineI386:  return core::Architecture::X86;
                case kMachineAMD64: return core::Architecture::X64;
                case kMachineARM64: return core::Architecture::ARM64;
                case kMachineARM:   return core::Architecture::ARM32;
                default:            return core::Architecture::Unknown;
            }
        }

        // Resolve IsWow64Process2 at runtime so we keep working on older
        // Windows that doesn't export it. Cache the resolved pointer.
        using IsWow64Process2_t = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);

        IsWow64Process2_t resolve_iswow64_process2() noexcept {
            static std::atomic<IsWow64Process2_t> cached{nullptr};
            static std::atomic<bool> tried{false};
            if (tried.load(std::memory_order_acquire)) {
                return cached.load(std::memory_order_acquire);
            }
            HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
            IsWow64Process2_t fn = nullptr;
            if (k32) {
                fn = reinterpret_cast<IsWow64Process2_t>(
                    ::GetProcAddress(k32, "IsWow64Process2"));
            }
            cached.store(fn, std::memory_order_release);
            tried.store(true, std::memory_order_release);
            return fn;
        }

        core::Architecture from_processor_arch(WORD a) noexcept {
            switch (a) {
                case PROCESSOR_ARCHITECTURE_INTEL: return core::Architecture::X86;
                case PROCESSOR_ARCHITECTURE_AMD64: return core::Architecture::X64;
                case PROCESSOR_ARCHITECTURE_ARM64: return core::Architecture::ARM64;
                case PROCESSOR_ARCHITECTURE_ARM:   return core::Architecture::ARM32;
                default:                            return core::Architecture::Unknown;
            }
        }
    } // namespace

    core::Architecture detect_native_architecture() {
        static std::atomic<core::Architecture> cached{core::Architecture::Unknown};
        static std::atomic<bool> done{false};
        if (done.load(std::memory_order_acquire)) {
            return cached.load(std::memory_order_acquire);
        }

        core::Architecture out = core::Architecture::Unknown;

        if (auto fn = resolve_iswow64_process2()) {
            USHORT process_machine = kMachineUnknown;
            USHORT native_machine  = kMachineUnknown;
            if (fn(::GetCurrentProcess(), &process_machine, &native_machine)) {
                out = from_machine(native_machine);
            }
        }

        if (out == core::Architecture::Unknown) {
            SYSTEM_INFO si{};
            ::GetNativeSystemInfo(&si);
            out = from_processor_arch(si.wProcessorArchitecture);
        }

        cached.store(out, std::memory_order_release);
        done.store(true, std::memory_order_release);
        return out;
    }

    core::Architecture detect_target_architecture(HANDLE process) {
        if (!process) return core::Architecture::Unknown;

        // Preferred path: IsWow64Process2 reports the actual machine type
        // of the target image, even on ARM64 hosts running x64 emulation.
        if (auto fn = resolve_iswow64_process2()) {
            USHORT process_machine = kMachineUnknown;
            USHORT native_machine  = kMachineUnknown;
            if (fn(process, &process_machine, &native_machine)) {
                if (process_machine == kMachineUnknown) {
                    // Per MSDN: kMachineUnknown means "the target is running
                    // natively at the host's architecture".
                    return from_machine(native_machine);
                }
                return from_machine(process_machine);
            }
        }

        // Fallback: IsWow64Process tells us only "wow64 yes/no". Combine
        // with the native arch we already detected.
        BOOL wow64 = FALSE;
        if (!::IsWow64Process(process, &wow64)) {
            return core::Architecture::Unknown;
        }
        const auto native = detect_native_architecture();
        if (wow64) {
            // 32-bit process running on a 64-bit OS. Could be x86 on either
            // x64 or ARM64; both surface here as x86.
            return core::Architecture::X86;
        }
        return native;
    }

} // namespace ura::platform
