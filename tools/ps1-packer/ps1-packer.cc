/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include <memory.h>

#include "flags.h"
#include "fmt/format.h"
#include "support/file.h"
#include "ucl/ucl.h"

extern "C" {
ucl_voidp ucl_memcpy(ucl_voidp dest, const ucl_voidp src, ucl_uint len) { return memcpy(dest, src, len); }
ucl_voidp ucl_memset(ucl_voidp s, int c, ucl_uint len) { return memset(s, c, len); }
}

int main(int argc, char** argv) {
    flags::args args(argc, argv);
    auto output = args.get<std::string>("o");

    auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    const bool shell = args.get<bool>("shell").value_or(false);
    const bool before = args.get<bool>("before").value_or(false);
    if (asksForHelp || !oneInput || !hasOutput) {
        fmt::print(R"(
Usage: {} input.ps-exe [-h] [-shell] [-before] -o output.ps-exe
  input.ps-exe      mandatory: specify the input ps-exe file.
  -o output.ps-exe  mandatory: name of the output file.
  -h                displays this help information and exit.
  -shell            adds a kernel reset stub; see documentation for details.
  -before           places the decompression routine before instead of after;
                    see documentation for details.
)",
                   argv[0]);
        return -1;
    }

    int ret = 0;

    for (auto& input : inputs) {
        PCSX::File* file = new PCSX::File(input);
        if (file->failed()) {
            fmt::print("Unable to open file: {}\n", input);
            ret = -1;
        } else {
            ucl_nrv2e_99_compress(nullptr, 0, nullptr, 0, nullptr, 9, nullptr, nullptr);
        }
        delete file;
    }

    return ret;
}
