// app/Orchestrator.cpp
#include "Orchestrator.hpp"

#include "../core/Logger.hpp"
#include "../engine/EngineContext.hpp"
#include "../platform/AcquisitionDiagnostic.hpp"
#include "../platform/Architecture.hpp"
#include "../platform/MemoryMap.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/ModuleEnumerator.hpp"
#include "../platform/ProcessEnumerator.hpp"
#include "../platform/ProcessHandle.hpp"
#include "../platform/StaticPELoader.hpp"

namespace ura::app {

    namespace {

        // Stamp every report with analyzer / target / native architecture
        // and the structured diagnostic, even on early-exit paths. Kept in
        // one place so CLI and GUI never disagree on what they show.
        void stamp_process_metadata(engine::AnalysisReport& r,
                                    const platform::AcquisitionDiagnostic& d,
                                    core::Pid pid,
                                    const std::wstring& name,
                                    const std::wstring& path) {
            r.process.pid  = pid;
            r.process.name = name;
            r.process.path = path;
            r.process.architecture          = core::to_string(d.target_architecture);
            r.process.analyzer_architecture = core::to_string(d.analyzer_architecture);
            r.process.native_architecture   = core::to_string(d.native_architecture);
            r.process.bitness               = core::bitness_of(d.target_architecture);
            r.acquisition = d;
        }

        // Best-effort static PE inspection. Runs only when live acquisition
        // already failed AND we have a usable file path. Populates
        // report.static_image so consumers can still fish offsets out of
        // the on-disk image. Address values inside this block are RVAs;
        // the standard runtime formula (`module_base + rva`) is documented
        // in the JSON.
        void try_static_fallback(engine::AnalysisReport& r,
                                 const std::wstring& path) {
            if (path.empty()) return;
            auto img = platform::StaticPELoader::load(path);
            if (!img) {
                URA_LOG_WARN("[STATIC] Fallback failed: %s",
                             img.error().message.c_str());
                r.warnings.push_back("Static fallback failed: " +
                                     img.error().message);
                return;
            }
            const auto& src = img.value();
            engine::ReportStaticImage dst;
            dst.present              = true;
            dst.file_path            = src.file_path;
            dst.file_name            = src.file_name;
            dst.is_64bit             = src.is_64bit;
            dst.machine              = src.machine;
            dst.timestamp            = src.timestamp;
            dst.image_base_preferred = src.image_base_preferred;
            dst.size_of_image        = src.size_of_image;
            dst.entry_point_rva      = src.entry_point_rva;
            dst.file_size_bytes      = src.file_size_bytes;
            dst.sections.reserve(src.sections.size());
            for (const auto& s : src.sections) dst.sections.push_back(s.name);
            dst.exports.reserve(src.exports.size());
            for (const auto& e : src.exports) {
                engine::ReportStaticExport ee;
                ee.name             = e.name;
                ee.ordinal          = e.ordinal;
                ee.rva              = e.rva;
                ee.is_forwarder     = e.is_forwarder;
                ee.forwarder_target = e.forwarder_target;
                dst.exports.push_back(std::move(ee));
            }
            r.static_image = std::move(dst);

            // Surface the named exports as a regular offset group so they
            // show up in the GUI Groups tab and in JSON. Per PROMPT.md
            // Tahap 6, addresses in static mode are RVAs.
            engine::ReportGroup grp;
            grp.name = "static.exports";
            grp.offsets.reserve(r.static_image.exports.size());
            for (const auto& e : r.static_image.exports) {
                if (e.name.empty()) continue;          // skip ordinal-only
                if (e.is_forwarder) continue;          // not real RVAs
                engine::ReportOffset off;
                off.label       = e.name;
                off.rva         = e.rva;
                off.absolute    = 0;                   // unknown until loaded
                off.module_name = r.static_image.file_name;
                off.notes       = "static: runtime = module_base + rva";
                grp.offsets.push_back(std::move(off));
            }
            if (!grp.offsets.empty()) r.groups.push_back(std::move(grp));
            r.notes["static.fallback"]      = "true";
            r.notes["static.section_count"] = std::to_string(r.static_image.sections.size());
            r.notes["static.export_count"]  = std::to_string(r.static_image.exports.size());
        }

        // Lift the platform memory-map summary into the engine-side struct.
        void copy_memory_map(engine::ReportMemoryMap& dst,
                             const platform::MemoryMapSummary& src) {
            dst.present               = true;
            dst.total_regions         = src.total_regions;
            dst.committed             = src.committed;
            dst.reserved              = src.reserved;
            dst.free_regions          = src.free_regions;
            dst.executable            = src.executable;
            dst.writable              = src.writable;
            dst.rwx                   = src.rwx;
            dst.image_regions         = src.image_regions;
            dst.mapped_regions        = src.mapped_regions;
            dst.private_regions       = src.private_regions;
            dst.total_committed_bytes = src.total_committed_bytes;

            dst.regions.reserve(src.regions.size());
            for (const auto& r : src.regions) {
                engine::ReportMemoryRegion er;
                er.base       = r.base;
                er.alloc_base = r.alloc_base;
                er.size       = r.size;
                er.state      = r.state_str;
                er.protect    = r.protect_str;
                er.type       = r.type_str;
                dst.regions.push_back(std::move(er));
            }

            if (src.rwx > 0) {
                dst.anomalies.push_back(std::to_string(src.rwx) +
                    " RWX region(s) — possible JIT or injected code.");
            }
            std::size_t priv_exec = 0;
            for (const auto& r : src.regions) {
                if (r.type == MEM_PRIVATE && r.is_executable()) ++priv_exec;
            }
            if (priv_exec > 0) {
                dst.anomalies.push_back(std::to_string(priv_exec) +
                    " executable MEM_PRIVATE region(s) — review for code "
                    "outside any loaded module.");
            }
        }

    } // namespace

    AnalyzeOutcome Orchestrator::analyze(const AnalyzeRequest& req) {
        AnalyzeOutcome outcome;
        engine::AnalysisReport& report = outcome.report;

        platform::AcquisitionDiagnostic d;
        d.analyzer_architecture = platform::analyzer_architecture();
        d.native_architecture   = platform::detect_native_architecture();

        // 1. Resolve PID + best-effort name/path.
        core::Pid pid = 0;
        std::wstring resolved_name;
        std::wstring resolved_path;
        if (req.pid) {
            pid = *req.pid;
        } else if (req.process_name) {
            auto p = platform::ProcessEnumerator::find_by_name(*req.process_name);
            if (!p) {
                d.status  = platform::AcquisitionStatus::ProcessNotFound;
                d.details = "Process not found: " + p.error().message;
                d.recommended_action = "Run --list-processes to verify "
                                       "the target is running.";
                stamp_process_metadata(report, d, 0, *req.process_name, L"");
                return outcome;
            }
            pid           = p.value().pid;
            resolved_name = p.value().name;
            resolved_path = p.value().full_path;
        } else {
            d.status  = platform::AcquisitionStatus::ProcessNotFound;
            d.details = "No --pid or --process specified.";
            stamp_process_metadata(report, d, 0, L"", L"");
            return outcome;
        }

        // 2. Open read-only handle.
        auto h = platform::ProcessHandle::open_for_read(pid);
        if (!h) {
            const int code = h.error().code;
            d.win32_error  = static_cast<std::uint32_t>(code);
            d.failed_api   = "OpenProcess";
            d.failed_stage = "open_for_read";
            d.details      = h.error().message;
            d.status = (code == 5)
                ? platform::AcquisitionStatus::AccessDenied
                : platform::AcquisitionStatus::OpenProcessFailed;
            d.recommended_action = (code == 5)
                ? "Run URA elevated, or pick a target you own. "
                  "Static fallback inspects the executable on disk."
                : "Verify the PID is still running.";
            stamp_process_metadata(report, d, pid, resolved_name, resolved_path);
            try_static_fallback(report, resolved_path);
            return outcome;
        }
        d.process_handle_opened = true;
        d.process_query_succeeded = h.value().full_query_access();
        d.target_architecture = h.value().architecture();

        // 3. Module enumeration. ModuleEnumerator returns its own diagnostic;
        // we merge it into ours and inherit the status.
        platform::MemoryReader reader(h.value());
        auto enum_result = platform::ModuleEnumerator::list(h.value());
        // Take the enumerator's diagnostic but preserve our own
        // architecture / handle flags (which it copied from us anyway).
        d = enum_result.diagnostic;
        if (!enum_result.success) {
            stamp_process_metadata(report, d, pid, resolved_name, resolved_path);
            try_static_fallback(report, resolved_path);
            return outcome;
        }
        outcome.acquired = true;

        // Fill in name/path from main module if --pid attach didn't resolve.
        if (resolved_name.empty() && !enum_result.modules.empty()) {
            resolved_name = enum_result.modules.front().name;
            resolved_path = enum_result.modules.front().full_path;
        }

        // 4. Build engine context.
        engine::EngineContext ctx{ h.value(), reader, enum_result.modules };

        // 5. Pick engine.
        const engine::IGameEngine* eng = nullptr;
        if (req.engine_id && !req.engine_id->empty()) {
            eng = registry_.find(*req.engine_id);
            if (!eng) {
                d.details = "Unknown engine id: " + *req.engine_id;
                d.recommended_action = "Use --list-engines to see registered engines.";
                stamp_process_metadata(report, d, pid, resolved_name, resolved_path);
                return outcome;
            }
        } else {
            eng = registry_.auto_detect(ctx);
            if (!eng) {
                d.details = "Auto-detect found no matching engine.";
                d.recommended_action = "Specify --engine generic_native to "
                                       "force the generic backend.";
                stamp_process_metadata(report, d, pid, resolved_name, resolved_path);
                return outcome;
            }
        }
        URA_LOG_INFO("[ENGINE] Using engine: %s (%s)",
                     eng->id().c_str(), eng->display_name().c_str());

        // 6. Engine analyze.
        auto rep = eng->analyze(ctx);
        if (!rep) {
            d.details = "Engine analysis failed: " + rep.error().message;
            stamp_process_metadata(report, d, pid, resolved_name, resolved_path);
            return outcome;
        }
        report = std::move(rep.value());
        outcome.analyzed = true;

        // 7. Memory-map snapshot. Engine-agnostic; attached after engine
        // runs so a slow walk can't poison engine timing.
        if (auto mm = platform::MemoryMapWalker::walk(h.value(),
                                                      /*keep_free=*/false)) {
            engine::ReportMemoryMap rm;
            copy_memory_map(rm, mm.value());
            report.memory_map = std::move(rm);
            const auto& s = mm.value();
            report.notes["memory.regions_total"]   = std::to_string(s.total_regions);
            report.notes["memory.committed_bytes"] = std::to_string(s.total_committed_bytes);
            report.notes["memory.rwx_regions"]     = std::to_string(s.rwx);
        } else {
            report.warnings.push_back("Memory map walk failed: " +
                                      mm.error().message);
        }

        stamp_process_metadata(report, d, pid, resolved_name, resolved_path);
        return outcome;
    }

} // namespace ura::app
