/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include <string>

#include "flags.h"
#include "fmt/format.h"
#include "support/file.h"
#include "supportpsx/psyq-obj.h"

using PCSX::PsyqLnkFile;

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    auto output = args.get<std::string>("o");

    auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h") || args.get<bool>("help");
    const bool noInput = inputs.size() == 0;
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    if (asksForHelp || noInput || (hasOutput && !oneInput)) {
        fmt::print(R"(
Usage: {} input.obj [input2.obj...] [-h] [-v] [-d] [-n] [-p prefix] [-o output.o]
  input.obj      mandatory: specifies the input psyq LNK object file.
  -h             displays this help information and exit.
  -v             turns on verbose mode for the parser.
  -d             displays the parsed input file.
  -n             uses "none" ABI instead of Linux.
  -p prefix      uses this prefix for local symbols.
  -s             sorts the sections and symbols by id, instead of order of appearance.
  -o output.o    tries to dump the parsed psyq LNK file into an ELF file;
                 can only work with a single input file.
  -b             outputs a big-endian ELF file.
  -c             enables use of ELF COMMON section;
                 by default .comm symbols are converted to .bss symbols.
)",
                   argv[0]);
        return -1;
    }

    bool verbose = !!args.get<bool>("v");

    int ret = 0;

    for (auto& input : inputs) {
        PCSX::IO<PCSX::File> file(new PCSX::PosixFile(input));
        if (file->failed()) {
            fmt::print(stderr, "Unable to open file: {}\n", input);
            ret = -2;
        } else {
            auto psyq = PsyqLnkFile::parse(file, verbose, !!args.get<bool>("s"), !args.get<bool>("c"));
            if (!psyq) {
                ret = -3;
            } else {
                if (args.get<bool>("d").value_or(false)) {
                    fmt::print(":: Displaying {}\n", input);
                    psyq->display();
                    fmt::print("\n\n\n");
                }
                if (hasOutput) {
                    fmt::print(":: Converting {} to {}...\n", input, output.value());
                    std::string prefix = args.get<std::string>("p").value_or("");
                    bool success = psyq->writeElf(prefix, output.value(), !!args.get<bool>("n"), !!args.get<bool>("b"));
                    if (success) {
                        fmt::print(":: Conversion completed.\n");
                    } else {
                        fmt::print(stderr, ":: Conversion failed: {}\n", psyq->elfConversionError);
                        ret = -4;
                    }
                }
            }
        }
        file.reset();
    }

    return ret;
}
