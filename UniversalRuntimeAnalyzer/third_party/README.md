# Third-party libraries

## nlohmann/json (single-header)

URA links against [nlohmann/json](https://github.com/nlohmann/json) for the
JSON exporter. The library is a single header and is **not** bundled with the
repository on purpose — pull whichever release you prefer.

### Setup

1. Download `json.hpp` from a release:
   <https://github.com/nlohmann/json/releases/latest>
2. Place it at:
   ```
   UniversalRuntimeAnalyzer/third_party/nlohmann/json.hpp
   ```

The vcxproj already adds `third_party` to the additional include directories,
so once the file is in place `#include <nlohmann/json.hpp>` resolves and the
project will compile.

### License

Single-header `json.hpp` is distributed under the MIT License by Niels Lohmann.
A copy of its license should accompany any redistribution of `json.hpp`.
