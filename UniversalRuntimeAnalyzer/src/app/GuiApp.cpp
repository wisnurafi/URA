// app/GuiApp.cpp
// Dear ImGui frontend for URA. Built only when URA_WITH_IMGUI is defined.
//
// The window hosts a top toolbar (process snapshot, engine select, run
// button) and a set of tabs (Modules, Groups, Memory Map, Classes, Notes
// & Warnings, Raw JSON). Each tab pulls from the same AnalysisReport
// produced by the regular CLI orchestrator path.
//
// We deliberately keep this file self-contained: backend init, render
// loop, view rendering, and orchestration all live here. The price is
// length; the benefit is no extra abstractions purely for the GUI.
#ifdef URA_WITH_IMGUI

#include "GuiApp.hpp"

#include "Orchestrator.hpp"
#include "../core/Logger.hpp"
#include "../engine/EngineContext.hpp"
#include "../export/JsonExporter.hpp"
#include "../platform/AcquisitionDiagnostic.hpp"
#include "../platform/MemoryMap.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/ModuleEnumerator.hpp"
#include "../platform/ProcessEnumerator.hpp"
#include "../platform/ProcessHandle.hpp"

#include <imgui.h>
#include <backends/imgui_impl_win32.h>
#include <backends/imgui_impl_dx11.h>

#include <d3d11.h>
#include <tchar.h>
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "dxgi.lib")

// External handler from imgui_impl_win32.cpp for input forwarding.
extern IMGUI_IMPL_API LRESULT
ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace ura::app {

    namespace {

        // ---------------- D3D11 plumbing ----------------
        struct D3DContext {
            ID3D11Device*           device = nullptr;
            ID3D11DeviceContext*    ctx    = nullptr;
            IDXGISwapChain*         swap   = nullptr;
            ID3D11RenderTargetView* rtv    = nullptr;
        };

        bool create_render_target(D3DContext& d) {
            ID3D11Texture2D* back = nullptr;
            if (FAILED(d.swap->GetBuffer(0, IID_PPV_ARGS(&back))) || !back)
                return false;
            const HRESULT hr = d.device->CreateRenderTargetView(back, nullptr, &d.rtv);
            back->Release();
            return SUCCEEDED(hr);
        }
        void release_render_target(D3DContext& d) {
            if (d.rtv) { d.rtv->Release(); d.rtv = nullptr; }
        }
        bool create_d3d(HWND hwnd, D3DContext& d) {
            DXGI_SWAP_CHAIN_DESC sd{};
            sd.BufferCount        = 2;
            sd.BufferDesc.Width   = 0;
            sd.BufferDesc.Height  = 0;
            sd.BufferDesc.Format  = DXGI_FORMAT_R8G8B8A8_UNORM;
            sd.BufferDesc.RefreshRate.Numerator   = 60;
            sd.BufferDesc.RefreshRate.Denominator = 1;
            sd.Flags        = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
            sd.BufferUsage  = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            sd.OutputWindow = hwnd;
            sd.SampleDesc.Count = 1;
            sd.SampleDesc.Quality = 0;
            sd.Windowed = TRUE;
            sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

            UINT flags = 0;
            D3D_FEATURE_LEVEL lvl;
            const D3D_FEATURE_LEVEL want[] = {
                D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0,
            };
            HRESULT hr = D3D11CreateDeviceAndSwapChain(
                nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                want, ARRAYSIZE(want), D3D11_SDK_VERSION,
                &sd, &d.swap, &d.device, &lvl, &d.ctx);
            if (hr == DXGI_ERROR_UNSUPPORTED) {
                hr = D3D11CreateDeviceAndSwapChain(
                    nullptr, D3D_DRIVER_TYPE_WARP, nullptr, flags,
                    want, ARRAYSIZE(want), D3D11_SDK_VERSION,
                    &sd, &d.swap, &d.device, &lvl, &d.ctx);
            }
            if (FAILED(hr)) return false;
            return create_render_target(d);
        }
        void cleanup_d3d(D3DContext& d) {
            release_render_target(d);
            if (d.swap)   { d.swap->Release();   d.swap   = nullptr; }
            if (d.ctx)    { d.ctx->Release();    d.ctx    = nullptr; }
            if (d.device) { d.device->Release(); d.device = nullptr; }
        }

        // ---------------- helpers ----------------
        std::string w2u(const std::wstring& w) {
            if (w.empty()) return {};
            int sz = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
            std::string out(sz, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                static_cast<int>(w.size()), out.data(), sz, nullptr, nullptr);
            return out;
        }

        std::string hex64(std::uint64_t v) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
            return buf;
        }
        std::string size_h(std::uint64_t v) {
            char buf[32];
            if (v >= (1ULL<<30)) std::snprintf(buf, sizeof(buf), "%.2f GiB", v / double(1ULL<<30));
            else if (v >= (1ULL<<20)) std::snprintf(buf, sizeof(buf), "%.2f MiB", v / double(1ULL<<20));
            else if (v >= (1ULL<<10)) std::snprintf(buf, sizeof(buf), "%.2f KiB", v / double(1ULL<<10));
            else std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(v));
            return buf;
        }

        // ---------------- AppState ----------------
        struct AppState {
            engine::EngineRegistry* registry = nullptr;

            // Process picker.
            std::vector<platform::ProcessInfo> processes;
            char process_filter[128] = "";
            int  selected_pid_idx = -1;

            // Engine selection.
            int  selected_engine = -1;       // -1 = auto-detect

            // Status / progress.
            std::string status = "Ready.";
            bool running = false;

            // Last report.
            std::optional<engine::AnalysisReport> report;
            std::string raw_json;

            // Filters per view.
            char modules_filter[128] = "";
            char groups_filter[128] = "";
            char regions_filter[128] = "";
            char classes_filter[128] = "";

            // Save dialog buffer.
            char save_path[MAX_PATH] = "report.json";
        };

        // ---------------- pipeline ----------------
        void refresh_processes(AppState& s) {
            auto snap = platform::ProcessEnumerator::snapshot();
            if (!snap) {
                s.status = "Process snapshot failed: " + snap.error().message;
                s.processes.clear();
                return;
            }
            s.processes = std::move(snap.value());
            std::sort(s.processes.begin(), s.processes.end(),
                [](const platform::ProcessInfo& a, const platform::ProcessInfo& b){
                    return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
                });
            s.status = "Listed " + std::to_string(s.processes.size()) + " processes.";
        }

        void run_analysis(AppState& s) {
            if (s.selected_pid_idx < 0
                || s.selected_pid_idx >= static_cast<int>(s.processes.size())) {
                s.status = "No process selected.";
                return;
            }
            const auto& proc = s.processes[s.selected_pid_idx];

            // Build the request and run the shared pipeline. The
            // orchestrator always returns a populated AnalysisReport, even
            // on failure paths, so we display whatever we got.
            AnalyzeRequest req;
            req.pid = proc.pid;
            if (s.selected_engine >= 0) {
                const auto all = s.registry->all();
                if (s.selected_engine < static_cast<int>(all.size())) {
                    req.engine_id = all[s.selected_engine]->id();
                }
            }

            Orchestrator orch(*s.registry);
            AnalyzeOutcome outcome = orch.analyze(req);
            auto& report = outcome.report;

            // The orchestrator may not know the process's display name when
            // attaching by PID — fill in from the process picker.
            if (report.process.name.empty()) report.process.name = proc.name;
            if (report.process.path.empty()) report.process.path = proc.full_path;

            s.raw_json = exporter::JsonExporter::to_string(report, /*pretty=*/true);
            s.report   = std::move(report);

            const auto status = s.report->acquisition.status;
            if (status == platform::AcquisitionStatus::Success) {
                s.status = "Analysis complete.";
            } else {
                s.status = std::string("Stopped at acquisition: ")
                         + platform::to_string(status);
            }
        }

        // ---------------- views ----------------
        void view_processes(AppState& s) {
            ImGui::Text("Process snapshot (%zu)", s.processes.size());
            ImGui::SameLine();
            if (ImGui::Button("Refresh")) refresh_processes(s);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(220);
            ImGui::InputTextWithHint("##pf", "filter by name...",
                                     s.process_filter, sizeof(s.process_filter));

            const std::string filter_lc = s.process_filter;
            std::string filter_lower; filter_lower.reserve(filter_lc.size());
            for (char c : filter_lc) filter_lower.push_back(
                static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

            if (ImGui::BeginTable("procs", 3,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("PID",  ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 220);
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (int i = 0; i < static_cast<int>(s.processes.size()); ++i) {
                    const auto& p = s.processes[i];
                    const std::string nm = w2u(p.name);
                    if (!filter_lower.empty()) {
                        std::string lnm; lnm.reserve(nm.size());
                        for (char c : nm) lnm.push_back(
                            static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                        if (lnm.find(filter_lower) == std::string::npos) continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    char pid_lbl[16];
                    std::snprintf(pid_lbl, sizeof(pid_lbl), "%lu",
                                  static_cast<unsigned long>(p.pid));
                    if (ImGui::Selectable(pid_lbl, s.selected_pid_idx == i,
                                          ImGuiSelectableFlags_SpanAllColumns)) {
                        s.selected_pid_idx = i;
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(nm.c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(w2u(p.full_path).c_str());
                }
                ImGui::EndTable();
            }
        }

        void view_modules(AppState& s) {
            if (!s.report) { ImGui::TextDisabled("No report yet."); return; }
            ImGui::Text("Modules: %zu", s.report->modules.size());
            ImGui::SameLine();
            ImGui::SetNextItemWidth(220);
            ImGui::InputTextWithHint("##mf", "filter...",
                                     s.modules_filter, sizeof(s.modules_filter));

            if (ImGui::BeginTable("mods", 6,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 240);
                ImGui::TableSetupColumn("Base");
                ImGui::TableSetupColumn("Size");
                ImGui::TableSetupColumn("Bits");
                ImGui::TableSetupColumn("Sections");
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                std::string flt = s.modules_filter;
                for (auto& c : flt) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                for (const auto& m : s.report->modules) {
                    const std::string nm = w2u(m.name);
                    if (!flt.empty()) {
                        std::string lnm = nm;
                        for (auto& c : lnm) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                        if (lnm.find(flt) == std::string::npos) continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(nm.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(hex64(m.base).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(size_h(m.size_of_image).c_str());
                    ImGui::TableNextColumn(); ImGui::Text("%d", m.is_64bit ? 64 : 32);
                    ImGui::TableNextColumn();
                    {
                        std::string secs;
                        for (const auto& sn : m.sections) {
                            if (!secs.empty()) secs += " ";
                            secs += sn;
                        }
                        ImGui::TextUnformatted(secs.c_str());
                    }
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(w2u(m.path).c_str());
                }
                ImGui::EndTable();
            }
        }

        void view_groups(AppState& s) {
            if (!s.report) { ImGui::TextDisabled("No report yet."); return; }

            std::size_t total = 0;
            for (const auto& g : s.report->groups) total += g.offsets.size();
            ImGui::Text("Groups: %zu (offsets: %zu)", s.report->groups.size(), total);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(220);
            ImGui::InputTextWithHint("##gf", "filter label/group...",
                                     s.groups_filter, sizeof(s.groups_filter));

            std::string flt = s.groups_filter;
            for (auto& c : flt) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            for (const auto& g : s.report->groups) {
                std::string g_lower = g.name;
                for (auto& c : g_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (!ImGui::CollapsingHeader(
                        (g.name + " (" + std::to_string(g.offsets.size()) + ")").c_str(),
                        ImGuiTreeNodeFlags_DefaultOpen))
                    continue;

                if (ImGui::BeginTable(g.name.c_str(), 5,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                    ImGuiTableFlags_Resizable))
                {
                    ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, 260);
                    ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 160);
                    ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 120);
                    ImGui::TableSetupColumn("Absolute", ImGuiTableColumnFlags_WidthFixed, 160);
                    ImGui::TableSetupColumn("Notes", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    for (const auto& o : g.offsets) {
                        if (!flt.empty()) {
                            std::string lab = o.label;
                            for (auto& c : lab) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                            if (lab.find(flt) == std::string::npos
                             && g_lower.find(flt) == std::string::npos)
                                continue;
                        }
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(o.label.c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(w2u(o.module_name).c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(hex64(o.rva).c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(hex64(o.absolute).c_str());
                        ImGui::TableNextColumn(); ImGui::TextUnformatted(o.notes.c_str());
                    }
                    ImGui::EndTable();
                }
            }
        }

        void view_memory_map(AppState& s) {
            if (!s.report || !s.report->memory_map.present) {
                ImGui::TextDisabled("No memory map captured.");
                return;
            }
            const auto& mm = s.report->memory_map;
            ImGui::Text("Total: %zu  Committed: %zu  RWX: %zu  Image: %zu  Mapped: %zu  Private: %zu",
                        mm.total_regions, mm.committed, mm.rwx,
                        mm.image_regions, mm.mapped_regions, mm.private_regions);
            ImGui::Text("Total committed: %s", size_h(mm.total_committed_bytes).c_str());
            for (const auto& a : mm.anomalies) {
                ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.4f, 1.0f), "! %s", a.c_str());
            }

            ImGui::SetNextItemWidth(220);
            ImGui::InputTextWithHint("##rf", "filter (protect/state/type)...",
                                     s.regions_filter, sizeof(s.regions_filter));

            std::string flt = s.regions_filter;
            for (auto& c : flt) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            if (ImGui::BeginTable("regions", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 160);
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 120);
                ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 120);
                ImGui::TableSetupColumn("Protect", ImGuiTableColumnFlags_WidthFixed, 260);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (const auto& r : mm.regions) {
                    if (!flt.empty()) {
                        std::string blob = r.protect + "|" + r.state + "|" + r.type;
                        for (auto& c : blob) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                        if (blob.find(flt) == std::string::npos) continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(hex64(r.base).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(size_h(r.size).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(r.state.c_str());
                    ImGui::TableNextColumn();
                    {
                        const bool rwx = r.protect.find("EXECUTE_READWRITE") != std::string::npos
                                      || r.protect.find("EXECUTE_WRITECOPY") != std::string::npos;
                        if (rwx) ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "%s", r.protect.c_str());
                        else     ImGui::TextUnformatted(r.protect.c_str());
                    }
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(r.type.c_str());
                }
                ImGui::EndTable();
            }
        }

        void view_classes(AppState& s) {
            if (!s.report) { ImGui::TextDisabled("No report yet."); return; }
            const auto& cs = s.report->classes;
            ImGui::Text("RTTI classes: %zu", cs.size());
            ImGui::SameLine();
            ImGui::SetNextItemWidth(220);
            ImGui::InputTextWithHint("##cf", "filter name...",
                                     s.classes_filter, sizeof(s.classes_filter));

            std::string flt = s.classes_filter;
            for (auto& c : flt) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            if (ImGui::BeginTable("classes", 6,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Class", ImGuiTableColumnFlags_WidthFixed, 320);
                ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 140);
                ImGui::TableSetupColumn("VFTable", ImGuiTableColumnFlags_WidthFixed, 140);
                ImGui::TableSetupColumn("VFTable RVA", ImGuiTableColumnFlags_WidthFixed, 120);
                ImGui::TableSetupColumn("Methods", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("Mangled", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();

                for (const auto& c : cs) {
                    if (!flt.empty()) {
                        std::string lnm = c.demangled_name + " " + c.mangled_name;
                        for (auto& ch : lnm) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                        if (lnm.find(flt) == std::string::npos) continue;
                    }
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(c.demangled_name.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(w2u(c.module_name).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(hex64(c.vftable_address).c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(hex64(c.vftable_rva).c_str());
                    ImGui::TableNextColumn(); ImGui::Text("%u", c.method_count);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(c.mangled_name.c_str());
                }
                ImGui::EndTable();
            }
        }

        void view_notes(AppState& s) {
            if (!s.report) { ImGui::TextDisabled("No report yet."); return; }
            ImGui::Text("Notes (%zu)", s.report->notes.size());
            if (ImGui::BeginTable("notes", 2,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Key",   ImGuiTableColumnFlags_WidthFixed, 320);
                ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                for (const auto& [k, v] : s.report->notes) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(k.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::Separator();
            ImGui::Text("Warnings (%zu)", s.report->warnings.size());
            for (const auto& w : s.report->warnings)
                ImGui::TextColored(ImVec4(1, 0.6f, 0.4f, 1), "%s", w.c_str());
        }

        // Map a status to an ImGui colour. Five tiers per
        // platform::StatusSeverity: success / warning / unsupported /
        // restricted / failed.
        ImVec4 colour_for(platform::AcquisitionStatus st) {
            switch (platform::severity_of(st)) {
                case platform::StatusSeverity::Success:     return ImVec4(0.4f, 0.9f, 0.5f, 1.0f);
                case platform::StatusSeverity::Warning:     return ImVec4(0.95f, 0.85f, 0.4f, 1.0f);
                case platform::StatusSeverity::Unsupported: return ImVec4(0.7f, 0.7f, 0.75f, 1.0f);
                case platform::StatusSeverity::Restricted:  return ImVec4(1.0f, 0.6f, 0.3f, 1.0f);
                case platform::StatusSeverity::Failed:      return ImVec4(1.0f, 0.45f, 0.45f, 1.0f);
            }
            return ImVec4(1, 1, 1, 1);
        }

        void view_diagnostics(AppState& s) {
            if (!s.report) { ImGui::TextDisabled("No report yet."); return; }
            const auto& d = s.report->acquisition;
            const auto colour = colour_for(d.status);

            ImGui::TextUnformatted("Status:");
            ImGui::SameLine();
            ImGui::TextColored(colour, "%s", platform::to_string(d.status));

            ImGui::Separator();
            ImGui::Text("Target");
            ImGui::Indent();
            ImGui::Text("PID:      %u", s.report->process.pid);
            ImGui::Text("Name:     %s", w2u(s.report->process.name).c_str());
            ImGui::Text("Path:     %s", w2u(s.report->process.path).c_str());
            ImGui::Unindent();

            ImGui::Separator();
            ImGui::Text("Architecture");
            ImGui::Indent();
            ImGui::Text("Analyzer: %s", core::to_string(d.analyzer_architecture));
            ImGui::Text("Target:   %s", core::to_string(d.target_architecture));
            ImGui::Text("Native:   %s", core::to_string(d.native_architecture));
            ImGui::Unindent();

            ImGui::Separator();
            ImGui::Text("Stages");
            ImGui::Indent();
            ImGui::Text("Process handle:        %s", d.process_handle_opened       ? "opened" : "not opened");
            ImGui::Text("Process query:         %s", d.process_query_succeeded     ? "ok"     : "failed/skipped");
            ImGui::Text("Module enumeration:    %s", d.module_enumeration_succeeded ? "ok"     : "failed/skipped");
            ImGui::Text("Memory read:           %s", d.memory_read_succeeded       ? "ok"     : "failed/skipped");
            ImGui::Text("Enumeration attempts:  %d", d.enumeration_attempts);
            ImGui::Unindent();

            if (d.win32_error != 0 || !d.failed_api.empty() || !d.failed_stage.empty()) {
                ImGui::Separator();
                ImGui::Text("Failure detail");
                ImGui::Indent();
                if (d.win32_error != 0)
                    ImGui::Text("Win32 error:  %u", d.win32_error);
                if (!d.failed_api.empty())
                    ImGui::Text("API:          %s", d.failed_api.c_str());
                if (!d.failed_stage.empty())
                    ImGui::Text("Stage:        %s", d.failed_stage.c_str());
                ImGui::Unindent();
            }

            if (!d.details.empty()) {
                ImGui::Separator();
                ImGui::Text("Diagnosis");
                ImGui::PushTextWrapPos(0.0f);
                ImGui::TextUnformatted(d.details.c_str());
                ImGui::PopTextWrapPos();
            }

            if (!d.recommended_action.empty()) {
                ImGui::Separator();
                ImGui::Text("Recommended action");
                ImGui::PushTextWrapPos(0.0f);
                ImGui::TextColored(ImVec4(0.7f, 0.85f, 1.0f, 1.0f),
                                   "%s", d.recommended_action.c_str());
                ImGui::PopTextWrapPos();
            }
        }

        void view_raw_json(AppState& s) {
            if (s.raw_json.empty()) { ImGui::TextDisabled("No report yet."); return; }
            if (ImGui::Button("Save to file...")) {
                ImGui::OpenPopup("save_json");
            }
            ImGui::SameLine();
            ImGui::Text("%zu bytes", s.raw_json.size());

            if (ImGui::BeginPopup("save_json")) {
                ImGui::InputText("Path", s.save_path, sizeof(s.save_path));
                if (ImGui::Button("Save")) {
                    FILE* f = nullptr;
                    fopen_s(&f, s.save_path, "wb");
                    if (f) {
                        std::fwrite(s.raw_json.data(), 1, s.raw_json.size(), f);
                        std::fclose(f);
                        s.status = std::string("Saved: ") + s.save_path;
                    } else {
                        s.status = std::string("Save failed: ") + s.save_path;
                    }
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
                ImGui::EndPopup();
            }

            ImGui::BeginChild("json_box", ImVec2(0, 0),
                              ImGuiChildFlags_Borders);
            // ImGui's text-input multiline is editable, which we don't want;
            // use a plain word-wrapped text block.
            ImGui::PushTextWrapPos(0.0f);
            ImGui::TextUnformatted(s.raw_json.data(),
                                   s.raw_json.data() + s.raw_json.size());
            ImGui::PopTextWrapPos();
            ImGui::EndChild();
        }

        // ---------------- top toolbar ----------------
        void view_toolbar(AppState& s) {
            const auto engines = s.registry->all();

            // Engine selector.
            ImGui::Text("Engine:");
            ImGui::SameLine();
            const char* current = (s.selected_engine < 0)
                ? "auto-detect"
                : engines[s.selected_engine]->display_name().c_str();
            ImGui::SetNextItemWidth(180);
            if (ImGui::BeginCombo("##engine", current)) {
                if (ImGui::Selectable("auto-detect", s.selected_engine < 0))
                    s.selected_engine = -1;
                for (int i = 0; i < static_cast<int>(engines.size()); ++i) {
                    const bool sel = (s.selected_engine == i);
                    if (ImGui::Selectable(engines[i]->display_name().c_str(), sel))
                        s.selected_engine = i;
                }
                ImGui::EndCombo();
            }
            ImGui::SameLine();

            // Run button.
            const bool can_run = s.selected_pid_idx >= 0;
            ImGui::BeginDisabled(!can_run || s.running);
            if (ImGui::Button("Analyze")) {
                s.running = true;
                run_analysis(s);
                s.running = false;
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextUnformatted(s.status.c_str());
        }

    } // namespace

    int GuiApp::run() {
        // Detach the inherited console. When URA is double-clicked from
        // File Explorer the OS allocates a fresh console (we link as
        // SubSystem=Console for CLI mode); FreeConsole dismisses that
        // window so the GUI is the only surface the user sees. When URA
        // is launched from an existing cmd.exe with --gui, this also
        // detaches us from the parent console — that's intentional, GUI
        // sessions don't write to stdout anyway.
        ::FreeConsole();

        AppState s;
        s.registry = &registry_;
        refresh_processes(s);

        WNDCLASSEXW wc{};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_CLASSDC;
        wc.lpfnWndProc   = [](HWND h, UINT m, WPARAM wp, LPARAM lp) -> LRESULT {
            if (ImGui_ImplWin32_WndProcHandler(h, m, wp, lp)) return TRUE;
            switch (m) {
                case WM_SIZE: {
                    auto* d = reinterpret_cast<D3DContext*>(
                        ::GetWindowLongPtrW(h, GWLP_USERDATA));
                    if (d && d->device && wp != SIZE_MINIMIZED) {
                        release_render_target(*d);
                        d->swap->ResizeBuffers(0, LOWORD(lp), HIWORD(lp),
                                               DXGI_FORMAT_UNKNOWN, 0);
                        create_render_target(*d);
                    }
                    return 0;
                }
                case WM_DESTROY: ::PostQuitMessage(0); return 0;
            }
            return ::DefWindowProcW(h, m, wp, lp);
        };
        wc.hInstance     = ::GetModuleHandleW(nullptr);
        wc.lpszClassName = L"URA_GUI";
        ::RegisterClassExW(&wc);

        HWND hwnd = ::CreateWindowExW(
            0, wc.lpszClassName, L"Universal Runtime Analyzer",
            WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
            nullptr, nullptr, wc.hInstance, nullptr);

        D3DContext d{};
        if (!create_d3d(hwnd, d)) {
            cleanup_d3d(d);
            ::DestroyWindow(hwnd);
            ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
            std::fprintf(stderr, "Failed to initialise D3D11.\n");
            return 1;
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&d));

        ::ShowWindow(hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(hwnd);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        ImGui::StyleColorsDark();
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(d.device, d.ctx);

        bool running = true;
        while (running) {
            MSG msg;
            while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                ::TranslateMessage(&msg);
                ::DispatchMessageW(&msg);
                if (msg.message == WM_QUIT) running = false;
            }
            if (!running) break;

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            const ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(vp->WorkPos);
            ImGui::SetNextWindowSize(vp->WorkSize);
            ImGui::Begin("URA##main", nullptr,
                ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoBringToFrontOnFocus);

            view_toolbar(s);
            ImGui::Separator();

            if (ImGui::BeginTabBar("tabs")) {
                if (ImGui::BeginTabItem("Processes"))   { view_processes(s);  ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Diagnostics")) { view_diagnostics(s); ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Modules"))     { view_modules(s);    ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Groups"))      { view_groups(s);     ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Memory Map")){ view_memory_map(s); ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Classes"))     { view_classes(s);    ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Notes"))       { view_notes(s);      ImGui::EndTabItem(); }
                if (ImGui::BeginTabItem("Raw JSON"))    { view_raw_json(s);   ImGui::EndTabItem(); }
                ImGui::EndTabBar();
            }
            ImGui::End();

            ImGui::Render();
            const float clear[4] = { 0.10f, 0.10f, 0.12f, 1.0f };
            d.ctx->OMSetRenderTargets(1, &d.rtv, nullptr);
            d.ctx->ClearRenderTargetView(d.rtv, clear);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            d.swap->Present(1, 0);
        }

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        cleanup_d3d(d);
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 0;
    }

} // namespace ura::app

#endif // URA_WITH_IMGUI
