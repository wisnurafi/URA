// app/CliApp.cpp
#include "CliApp.hpp"

#include "Orchestrator.hpp"
#include "../core/Logger.hpp"
#include "../export/JsonExporter.hpp"
#include "../platform/AcquisitionDiagnostic.hpp"
#include "../platform/Architecture.hpp"
#include "../platform/ProcessEnumerator.hpp"
#include "../platform/StaticPELoader.hpp"

#ifdef _WIN32
#  include <windows.h>
#endif

#include <cstdio>
#include <iostream>
#include <sstream>

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

        // Render the structured acquisition diagnostic to stderr in the
        // multi-line block format from PROMPT.md Tahap 5. Always called on
        // failure paths; optionally called on success in --verbose mode.
        void print_diagnostic(const engine::AnalysisReport& r,
                              const char* stage_label) {
            const auto& d = r.acquisition;
            std::ostringstream os;
            os << "\nAnalysis stopped at: " << stage_label << "\n\n"
               << "Target:\n"
               << "  PID:                  " << r.process.pid << '\n'
               << "  Name:                 " << w2u(r.process.name) << '\n'
               << "  Path:                 " << w2u(r.process.path) << "\n\n"
               << platform::format_diagnostic(d);
            std::fputs(os.str().c_str(), stderr);
        }

        // Map a diagnostic status to a CLI exit code. The orchestrator
        // collapses many failure modes into structured states; we map them
        // back to small integers for shell scripts.
        int exit_code_for(platform::AcquisitionStatus s) {
            switch (s) {
                case platform::AcquisitionStatus::Success:               return 0;
                case platform::AcquisitionStatus::ProcessNotFound:       return 2;
                case platform::AcquisitionStatus::OpenProcessFailed:
                case platform::AcquisitionStatus::AccessDenied:          return 3;
                case platform::AcquisitionStatus::ArchitectureMismatch:  return 9;
                case platform::AcquisitionStatus::ProcessTerminated:
                case platform::AcquisitionStatus::LoaderTransition:
                case platform::AcquisitionStatus::PartialCopy:
                case platform::AcquisitionStatus::ModuleEnumerationFailed:
                case platform::AcquisitionStatus::MemoryReadRestricted:
                case platform::AcquisitionStatus::ProtectedOrRestricted: return 4;
                default:                                                 return 1;
            }
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
        // Static-only mode. Inspect a PE file on disk without ever opening
        // a process handle. Useful for permission-denied targets or pure
        // offline analysis.
        if (args.static_pe_path) {
            auto img = platform::StaticPELoader::load(*args.static_pe_path);
            if (!img) {
                std::fprintf(stderr, "Static PE load failed: %s\n",
                             img.error().message.c_str());
                return 4;
            }
            engine::AnalysisReport report;
            report.engine_id           = "static";
            report.engine_display_name = "Static PE";
            report.process.path        = img.value().file_path;
            report.process.name        = img.value().file_name;
            report.process.architecture = img.value().is_64bit ? "x64" : "x86";
            report.process.bitness     = img.value().is_64bit ? 64 : 32;
            report.process.analyzer_architecture =
                core::to_string(platform::analyzer_architecture());
            report.process.native_architecture =
                core::to_string(platform::detect_native_architecture());
            report.acquisition.status = platform::AcquisitionStatus::Success;
            report.acquisition.analyzer_architecture = platform::analyzer_architecture();
            report.acquisition.native_architecture   = platform::detect_native_architecture();
            report.acquisition.target_architecture =
                img.value().is_64bit ? core::Architecture::X64
                                     : core::Architecture::X86;
            report.acquisition.details = "Static PE inspection (disk only).";

            engine::ReportStaticImage dst;
            dst.present              = true;
            dst.file_path            = img.value().file_path;
            dst.file_name            = img.value().file_name;
            dst.is_64bit             = img.value().is_64bit;
            dst.machine              = img.value().machine;
            dst.timestamp            = img.value().timestamp;
            dst.image_base_preferred = img.value().image_base_preferred;
            dst.size_of_image        = img.value().size_of_image;
            dst.entry_point_rva      = img.value().entry_point_rva;
            dst.file_size_bytes      = img.value().file_size_bytes;
            for (const auto& s : img.value().sections) dst.sections.push_back(s.name);
            for (const auto& e : img.value().exports) {
                engine::ReportStaticExport ee;
                ee.name             = e.name;
                ee.ordinal          = e.ordinal;
                ee.rva              = e.rva;
                ee.is_forwarder     = e.is_forwarder;
                ee.forwarder_target = e.forwarder_target;
                dst.exports.push_back(std::move(ee));
            }
            report.static_image = std::move(dst);

            // Mirror exports into a regular offset group.
            engine::ReportGroup grp;
            grp.name = "static.exports";
            for (const auto& e : report.static_image.exports) {
                if (e.name.empty() || e.is_forwarder) continue;
                engine::ReportOffset off;
                off.label       = e.name;
                off.rva         = e.rva;
                off.module_name = report.static_image.file_name;
                off.notes       = "static: runtime = module_base + rva";
                grp.offsets.push_back(std::move(off));
            }
            if (!grp.offsets.empty()) report.groups.push_back(std::move(grp));

            if (args.out_path) {
                auto w = exporter::JsonExporter::write_file(report, *args.out_path,
                                                            args.pretty);
                if (!w) {
                    std::fprintf(stderr, "Export failed: %s\n",
                                 w.error().message.c_str());
                    return 8;
                }
                std::printf("OK: %s (%zu sections, %zu exports)\n",
                            args.out_path->c_str(),
                            report.static_image.sections.size(),
                            report.static_image.exports.size());
            } else {
                std::cout << exporter::JsonExporter::to_string(report, args.pretty)
                          << '\n';
            }
            return 0;
        }

        if (!args.pid && !args.process_name) {
            std::fprintf(stderr,
                         "Specify --pid or --process. Use --help for usage.\n");
            return 64;
        }

        // Build the request and run the shared pipeline.
        AnalyzeRequest req;
        req.pid          = args.pid;
        req.process_name = args.process_name;
        req.engine_id    = args.engine_id;

        Orchestrator orch(registry_);
        AnalyzeOutcome outcome = orch.analyze(req);

        const auto& report = outcome.report;
        const auto status = report.acquisition.status;

        // Failure path: render the structured diagnostic and bail with a
        // status-specific exit code. No "anti-cheat" verdict.
        if (status != platform::AcquisitionStatus::Success) {
            const char* stage = !outcome.acquired ? "Module Enumeration"
                              : !outcome.analyzed ? "Engine Analysis"
                              : "Post-analysis";
            print_diagnostic(report, stage);

            // Static fallback may still have produced useful data
            // (sections, exports, entry RVA from disk). Emit the JSON if
            // the user asked for an output file so they can use it.
            if (args.out_path && report.static_image.present) {
                auto w = exporter::JsonExporter::write_file(report, *args.out_path,
                                                            args.pretty);
                if (w) {
                    std::fprintf(stderr,
                        "\nStatic fallback emitted: %s "
                        "(%zu section(s), %zu export(s))\n",
                        args.out_path->c_str(),
                        report.static_image.sections.size(),
                        report.static_image.exports.size());
                }
            }
            return exit_code_for(status);
        }

        // Success: emit the JSON report.
        if (args.out_path) {
            auto w = exporter::JsonExporter::write_file(report, *args.out_path,
                                                       args.pretty);
            if (!w) {
                std::fprintf(stderr, "Export failed: %s\n",
                             w.error().message.c_str());
                return 8;
            }
            std::printf("OK: %s (%zu groups, %zu modules)\n",
                        args.out_path->c_str(),
                        report.groups.size(),
                        report.modules.size());
        } else {
            std::cout << exporter::JsonExporter::to_string(report, args.pretty)
                      << '\n';
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
