// engine/AnalysisReport.cpp
#include "AnalysisReport.hpp"

#include <algorithm>

namespace ura::engine {

    void AnalysisReport::add_offset(std::string group_name, ReportOffset off) {
        auto it = std::find_if(groups.begin(), groups.end(),
            [&](const ReportGroup& g) { return g.name == group_name; });
        if (it == groups.end()) {
            ReportGroup g;
            g.name = std::move(group_name);
            g.offsets.push_back(std::move(off));
            groups.push_back(std::move(g));
        } else {
            it->offsets.push_back(std::move(off));
        }
    }

} // namespace ura::engine
