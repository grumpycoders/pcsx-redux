/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "args/args.hxx"
#include "fmt/format.h"

namespace PCSX {
namespace ToolArgs {

// Parses the command line of one of the command line tools. The flags use a single
// dash (-o output.bin), and a value can be given either as the next argument or
// packed with an equal sign (-o=output.bin). For compatibility, a declared flag can
// also be spelled with more dashes (--o output.bin). Unknown flags and malformed
// values are errors: the message is printed on stderr, and every flag and positional
// argument is reset, so the tool sees an empty command line and prints its usage.
inline void parse(args::ArgumentParser& parser, int argc, char** argv) {
    parser.LongPrefix("-");
    parser.ShortPrefix("-");

    auto findFlag = [&parser](std::string_view name) -> args::FlagBase* {
        for (auto flag : parser.GetAllFlags()) {
            if (flag->GetMatcher().Match(args::EitherFlag(std::string(name)))) return flag;
        }
        return nullptr;
    };

    std::vector<std::string> arguments;
    bool expectingValue = false;
    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (expectingValue) {
            expectingValue = false;
            arguments.emplace_back(arg);
            continue;
        }
        auto dashes = arg.find_first_not_of('-');
        if (dashes == 0 || dashes == std::string_view::npos) {
            arguments.emplace_back(arg);
            continue;
        }
        auto stripped = arg.substr(dashes);
        auto equal = stripped.find('=');
        auto flag = findFlag(stripped.substr(0, equal));
        if (!flag) {
            arguments.emplace_back(arg);
            continue;
        }
        expectingValue = equal == std::string_view::npos && flag->NumberOfArguments().min > 0;
        arguments.emplace_back("-" + std::string(stripped));
    }

    try {
        parser.ParseArgs(arguments);
    } catch (const args::Error& e) {
        fmt::print(stderr, "{}\n", e.what());
        parser.Reset();
    }
}

// The value of a flag, or nullopt if it wasn't on the command line. When a flag
// is repeated, the last occurrence wins.
template <typename T>
std::optional<T> get(args::ValueFlag<T>& flag) {
    if (!flag) return std::nullopt;
    return args::get(flag);
}

}  // namespace ToolArgs
}  // namespace PCSX
