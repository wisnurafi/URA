// platform/AcquisitionDiagnostic.cpp
#include "AcquisitionDiagnostic.hpp"

#include <sstream>

namespace ura::platform {

    std::string format_diagnostic(const AcquisitionDiagnostic& d) {
        std::ostringstream os;
        os << "Status:               " << to_string(d.status)               << '\n';

        if (d.win32_error != 0) {
            os << "Win32 error:          " << d.win32_error << '\n';
        }
        if (!d.failed_api.empty()) {
            os << "Failed API:           " << d.failed_api << '\n';
        }
        if (!d.failed_stage.empty()) {
            os << "Failed stage:         " << d.failed_stage << '\n';
        }

        os << "Analyzer architecture: " << core::to_string(d.analyzer_architecture) << '\n'
           << "Target architecture:   " << core::to_string(d.target_architecture)   << '\n'
           << "Native architecture:   " << core::to_string(d.native_architecture)   << '\n';

        os << "Process handle:       " << (d.process_handle_opened       ? "opened" : "not opened") << '\n';
        os << "Process query:        " << (d.process_query_succeeded     ? "ok"     : "failed/skipped") << '\n';
        os << "Module enumeration:   " << (d.module_enumeration_succeeded ? "ok"     : "failed/skipped") << '\n';
        os << "Memory read:          " << (d.memory_read_succeeded       ? "ok"     : "failed/skipped") << '\n';

        if (d.enumeration_attempts > 0) {
            os << "Enumeration attempts: " << d.enumeration_attempts << '\n';
        }
        if (!d.details.empty()) {
            os << "Details:              " << d.details << '\n';
        }
        if (!d.recommended_action.empty()) {
            os << "Recommended action:   " << d.recommended_action << '\n';
        }

        return os.str();
    }

} // namespace ura::platform
