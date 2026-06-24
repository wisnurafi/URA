// app/ArgParser.cpp
#include "ArgParser.hpp"

#include <cstring>
#include <sstream>
#include <string>

namespace ura::app {

    namespace {
        std::wstring narrow_to_wide(const std::string& s) {
            // ASCII-only path — argv strings on Windows for our use case
            // (executable names) are always ASCII or near-ASCII.
            return std::wstring(s.begin(), s.end());
        }

        bool starts_with(const char* s, const char* prefix) {
            return std::strncmp(s, prefix, std::strlen(prefix)) == 0;
        }
    } // namespace

    std::string help_text() {
        std::ostringstream os;
        os <<
"Universal Runtime Analyzer (URA) — read-only memory analysis framework\n"
"\n"
"Usage: URA.exe [options]\n"
"\n"
"Subject selection (one of):\n"
"  --pid <N>                 Attach to process by PID\n"
"  --process <name.exe>      Attach to first process matching this name\n"
"  --static-pe <path>        Inspect a PE file on disk (no process attach)\n"
"\n"
"Engine selection:\n"
"  --auto                    Auto-detect engine (default)\n"
"  --engine <id>             Force a specific engine\n"
"\n"
"Output:\n"
"  --out <path>              Write JSON report to <path>\n"
"  --compact                 Emit compact JSON (default: pretty)\n"
"\n"
"Modes:\n"
"  --gui                     Launch the Dear ImGui frontend (if compiled in)\n"
"  --list-processes          List visible processes and exit\n"
"  --list-engines            List registered engines and exit\n"
"  --version                 Print version and exit\n"
"  -h, --help                Show this help\n"
"\n"
"Diagnostics:\n"
"  -v, --verbose             Verbose logging (debug)\n"
"  -q, --quiet               Quiet logging (warn+)\n"
"\n"
"Examples:\n"
"  URA.exe --list-processes\n"
"  URA.exe --pid 1234 --auto --out report.json\n"
"  URA.exe --process GooseGooseDuck.exe --engine unity_il2cpp --out ggd.json\n"
"\n"
"NOTE: URA opens the target process with PROCESS_QUERY_INFORMATION |\n"
"      PROCESS_VM_READ. It does not write target memory. Designed for\n"
"      offline / authorised targets — software you own, open-source\n"
"      applications, crackmes, and authorised testing environments.\n";
        return os.str();
    }

    ArgParseResult parse(int argc, char** argv) {
        ArgParseResult r;
        auto fail = [&](std::string msg) {
            r.ok = false;
            r.error = std::move(msg);
            return r;
        };

        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];

            auto next = [&](const char* opt) -> std::string {
                if (i + 1 >= argc) {
                    r.ok = false;
                    r.error = std::string(opt) + " requires an argument";
                    return {};
                }
                return std::string(argv[++i]);
            };

            if (a == "-h" || a == "--help")           { r.args.show_help = true; }
            else if (a == "--version")                { r.args.show_version = true; }
            else if (a == "-v" || a == "--verbose")   { r.args.verbose = true; }
            else if (a == "-q" || a == "--quiet")     { r.args.quiet = true; }
            else if (a == "--gui")                    { r.args.gui = true; }
            else if (a == "--list-processes")         { r.args.list_processes = true; }
            else if (a == "--list-engines")           { r.args.list_engines = true; }
            else if (a == "--auto")                   { r.args.auto_detect = true; }
            else if (a == "--compact")                { r.args.pretty = false; }
            else if (a == "--pid") {
                auto v = next("--pid"); if (!r.ok) return r;
                try {
                    r.args.pid = static_cast<std::uint32_t>(std::stoul(v));
                } catch (...) { return fail("invalid --pid value: " + v); }
            }
            else if (a == "--process") {
                auto v = next("--process"); if (!r.ok) return r;
                r.args.process_name = narrow_to_wide(v);
            }
            else if (a == "--static-pe") {
                auto v = next("--static-pe"); if (!r.ok) return r;
                r.args.static_pe_path = narrow_to_wide(v);
            }
            else if (a == "--engine") {
                auto v = next("--engine"); if (!r.ok) return r;
                r.args.engine_id = v;
                r.args.auto_detect = false;
            }
            else if (a == "--out") {
                auto v = next("--out"); if (!r.ok) return r;
                r.args.out_path = v;
            }
            else {
                return fail("unknown argument: " + a);
            }
        }

        return r;
    }

} // namespace ura::app
