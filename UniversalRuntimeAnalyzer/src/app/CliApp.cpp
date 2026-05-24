// app/CliApp.cpp
#include "CliApp.hpp"

#include "../core/Logger.hpp"
#include "../engine/EngineContext.hpp"
#include "../export/JsonExporter.hpp"
#include "../platform/MemoryMap.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/ModuleEnumerator.hpp"
#include "../platform/ProcessEnumerator.hpp"
#include "../platform/ProcessHandle.hpp"

#ifdef _WIN32
#  include <windows.h>
#endif

#include <cstdio>
#include <iostream>

namespace ura::app {

    using core::LogLevel;
    using core::Logger;

    namespace {
        std::string w2u(const std::wstring& w) {
        #ifdef _WIN32
            if (w.empty()) return {};
            int sz = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                           nullptr, 0, nullptr, nullptr);
            std::string out(sz, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                  out.data(), sz, nullptr, nullptr);
            return out;
        #else
            return std::string(w.begin(), w.end());
        #endif
        }
    } // namespace

    int CliApp::cmd_list_processes() const {
        auto snap = platform::ProcessEnumerator::snapshot();
        if (!snap) {
            std::fprintf(stderr, "Failed to enumerate processes: %s\n",
                         snap.error().message.c_str());
            return 1;
        }
        std::printf("%6s  %-32s  %s\n", "PID", "NAME", "PATH");
        for (const auto& p : snap.value()) {
            std::printf("%6lu  %-32s  %s\n",
                        (unsigned long)p.pid,
                        w2u(p.name).c_str(),
                        w2u(p.full_path).c_str());
        }
        return 0;
    }

    int CliApp::cmd_list_engines() const {
        std::printf("%-20s  %s\n", "ID", "DISPLAY NAME");
        for (const auto* e : registry_.all()) {
            std::printf("%-20s  %s\n", e->id().c_str(), e->display_name().c_str());
        }
        return 0;
    }

    int CliApp::cmd_analyze(const CliArgs& args) {
        // 1. Resolve PID.
        core::Pid pid = 0;
        std::wstring resolved_name;
        std::wstring resolved_path;
        if (args.pid) {
            pid = *args.pid;
        } else if (args.process_name) {
            auto p = platform::ProcessEnumerator::find_by_name(*args.process_name);
            if (!p) {
                std::fprintf(stderr, "Process not found: %s\n",
                             w2u(*args.process_name).c_str());
                return 2;
            }
            pid           = p.value().pid;
            resolved_name = p.value().name;
            resolved_path = p.value().full_path;
        } else {
            std::fprintf(stderr, "Specify --pid or --process. Use --help for usage.\n");
            return 64;
        }

        // 2. Open read-only handle.
        auto h = platform::ProcessHandle::open_for_read(pid);
        if (!h) {
            std::fprintf(stderr, "OpenProcess failed for pid %lu: %s\n",
                         (unsigned long)pid, h.error().message.c_str());
            return 3;
        }

        // 3. Snapshot modules.
        platform::MemoryReader reader(h.value());
        auto mods = platform::ModuleEnumerator::list(h.value());
        if (!mods) {
            std::fprintf(stderr, "Module enumeration failed: %s\n",
                         mods.error().message.c_str());
            return 4;
        }

        // Try to fill resolved_name/path if we attached by PID directly.
        if (resolved_name.empty() && !mods.value().empty()) {
            resolved_name = mods.value().front().name;
            resolved_path = mods.value().front().full_path;
        }

        // 4. Build engine context.
        engine::EngineContext ctx{ h.value(), reader, mods.value() };

        // 5. Pick engine.
        const engine::IGameEngine* eng = nullptr;
        if (args.engine_id) {
            eng = registry_.find(*args.engine_id);
            if (!eng) {
                std::fprintf(stderr, "Unknown engine id: %s\n",
                             args.engine_id->c_str());
                return 5;
            }
        } else {
            eng = registry_.auto_detect(ctx);
            if (!eng) {
                std::fprintf(stderr, "Auto-detect found no matching engine.\n");
                return 6;
            }
        }
        URA_LOG_INFO("Using engine: %s (%s)",
                     eng->id().c_str(), eng->display_name().c_str());

        // 6. Analyze.
        auto rep = eng->analyze(ctx);
        if (!rep) {
            std::fprintf(stderr, "Analysis failed: %s\n", rep.error().message.c_str());
            return 7;
        }
        auto& report = rep.value();
        report.process.pid       = pid;
        report.process.name      = resolved_name;
        report.process.path      = resolved_path;
        report.process.is_wow64  = h.value().is_wow64();
        report.process.bitness   = h.value().bitness();

        // 6b. Address-space snapshot. Engine-agnostic; we attach it after
        //     the engine runs so a slow walk can't poison engine timing,
        //     and so engines that fail still produce no memory map noise.
        if (auto mm = platform::MemoryMapWalker::walk(h.value(),
                                                      /*keep_free=*/false)) {
            const auto& s = mm.value();
            engine::ReportMemoryMap rm;
            rm.present               = true;
            rm.total_regions         = s.total_regions;
            rm.committed             = s.committed;
            rm.reserved              = s.reserved;
            rm.free_regions          = s.free_regions;
            rm.executable            = s.executable;
            rm.writable              = s.writable;
            rm.rwx                   = s.rwx;
            rm.image_regions         = s.image_regions;
            rm.mapped_regions        = s.mapped_regions;
            rm.private_regions       = s.private_regions;
            rm.total_committed_bytes = s.total_committed_bytes;

            rm.regions.reserve(s.regions.size());
            for (const auto& r : s.regions) {
                engine::ReportMemoryRegion er;
                er.base       = r.base;
                er.alloc_base = r.alloc_base;
                er.size       = r.size;
                er.state      = r.state_str;
                er.protect    = r.protect_str;
                er.type       = r.type_str;
                rm.regions.push_back(std::move(er));
            }

            // Anomaly heuristics: RWX and private executable regions are
            // both classic injection / JIT signals worth surfacing.
            if (s.rwx > 0) {
                rm.anomalies.push_back(std::to_string(s.rwx) +
                    " RWX region(s) — possible JIT or injected code.");
            }
            std::size_t priv_exec = 0;
            for (const auto& r : s.regions) {
                if (r.type == MEM_PRIVATE && r.is_executable()) ++priv_exec;
            }
            if (priv_exec > 0) {
                rm.anomalies.push_back(std::to_string(priv_exec) +
                    " executable MEM_PRIVATE region(s) — review for code "
                    "outside any loaded module.");
            }

            report.memory_map = std::move(rm);
            report.notes["memory.regions_total"]   = std::to_string(s.total_regions);
            report.notes["memory.committed_bytes"] = std::to_string(s.total_committed_bytes);
            report.notes["memory.rwx_regions"]     = std::to_string(s.rwx);
        } else {
            report.warnings.push_back("Memory map walk failed: " +
                                      mm.error().message);
        }

        // 7. Output.
        if (args.out_path) {
            auto w = exporter::JsonExporter::write_file(report, *args.out_path,
                                                       args.pretty);
            if (!w) {
                std::fprintf(stderr, "Export failed: %s\n", w.error().message.c_str());
                return 8;
            }
            std::printf("OK: %s (%zu groups, %zu modules)\n",
                        args.out_path->c_str(), report.groups.size(),
                        report.modules.size());
        } else {
            std::cout << exporter::JsonExporter::to_string(report, args.pretty) << '\n';
        }
        return 0;
    }

    int CliApp::run(const CliArgs& args) {
        if (args.show_help) {
            std::cout << help_text();
            return 0;
        }
        if (args.show_version) {
            std::cout << "URA 0.1.0\n";
            return 0;
        }
        if (args.verbose) Logger::instance().set_level(LogLevel::Debug);
        if (args.quiet)   Logger::instance().set_level(LogLevel::Warn);

        if (args.list_processes) return cmd_list_processes();
        if (args.list_engines)   return cmd_list_engines();

        return cmd_analyze(args);
    }

} // namespace ura::app
