// platform/MemoryReader.hpp
// Read-only wrapper over ReadProcessMemory.
//
// Design rule: this header MUST NOT expose any write or remote-execution
// API. If you find yourself wanting to add WriteProcessMemory here, stop —
// that is out of scope (see docs/ETHICS.md).
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "ProcessHandle.hpp"

#include <cstring>
#include <type_traits>
#include <vector>

namespace ura::platform {

    class MemoryReader {
    public:
        explicit MemoryReader(const ProcessHandle& proc) : proc_(proc) {}

        // Bulk raw read. Returns a buffer of exactly `size` bytes on success.
        core::Result<core::ByteBuffer> read_raw(core::Address addr,
                                                std::size_t size) const;

        // Best-effort raw read: returns however many bytes were readable
        // before the first failure. Useful for region scanning where a
        // page may straddle unreadable memory.
        core::ByteBuffer read_raw_best_effort(core::Address addr,
                                              std::size_t size) const;

        // Typed read of a trivially-copyable value.
        template <typename T>
        core::Result<T> read(core::Address addr) const {
            static_assert(std::is_trivially_copyable_v<T>,
                          "MemoryReader::read<T> requires trivially copyable T");
            T value{};
            auto r = read_into(addr, &value, sizeof(T));
            if (!r) return r.error();
            return value;
        }

        // Read into a caller-provided buffer.
        core::Result<void> read_into(core::Address addr,
                                     void* dst,
                                     std::size_t size) const;

        // Pointer chain: start at `base`, repeatedly read a pointer at
        // `current + offsets[i]`, then add the final offset (if any pattern
        // is `[base + o0]+o1 = ptr; [ptr]+o2 = ptr; ...`). For typical
        // engines the convention used by ReClass is followed.
        core::Result<core::Address>
            walk_pointer_chain(core::Address base,
                               const std::vector<std::ptrdiff_t>& offsets) const;

        // Read a null-terminated UTF-8 string, capped at max_len.
        core::Result<std::string>
            read_cstring(core::Address addr, std::size_t max_len = 512) const;

        // Read a null-terminated UTF-16LE string, capped at max_len wchars.
        core::Result<std::wstring>
            read_wstring(core::Address addr, std::size_t max_len = 512) const;

    private:
        const ProcessHandle& proc_;
    };

} // namespace ura::platform
