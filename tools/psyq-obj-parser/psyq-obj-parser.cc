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

#include <list>

#include "elfio/elfio.hpp"
#include "flags.h"
#include "support/file.h"
#include "support/hashtable.h"
#include "support/slice.h"

#define vprint(...) \
    if (s_verbose) fmt::print(__VA_ARGS__)

static bool s_verbose = false;

enum class PsyqOpcode : uint8_t {
    END = 0,
    BYTES = 2,
    SWITCH = 6,
    ZEROES = 8,
    RELOCATION = 10,
    EXPORTED_SYMBOL = 12,
    IMPORTED_SYMBOL = 14,
    SECTION = 16,
    PROGRAMTYPE = 46,
    UNINITIALIZED = 48,
};

enum class PsyqRelocType : uint8_t {
    REL32 = 16,
    REL26 = 74,
    HI16 = 82,
    LO16 = 84,
};

enum class PsyqExprOpcode : uint8_t {
    VALUE = 0,
    IMPORT = 2,
    SECTION_BASE = 4,
    SECTION_START = 12,
    SECTION_END = 22,
    ADD = 44,
    SUB = 46,
    DIV = 50,
};

struct PsyqExpression {
    PsyqExprOpcode type;
    std::unique_ptr<PsyqExpression> left = nullptr;
    std::unique_ptr<PsyqExpression> right = nullptr;
    uint32_t value;
    uint16_t import;
    uint16_t sectionIndex;
};

struct PsyqRelocation {
    PsyqRelocType type;
    uint32_t offset;
    std::unique_ptr<PsyqExpression> expression;
};

struct PsyqLnkFile {
    struct Section;
    struct Symbol;
    typedef PCSX::Intrusive::HashTable<uint16_t, Section> SectionHashTable;
    typedef PCSX::Intrusive::HashTable<uint16_t, Symbol> SymbolHashTable;
    struct Section : public SectionHashTable::Node {
        uint16_t group;
        uint8_t alignment;
        std::string name;
        uint32_t zeroes = 0;
        uint32_t uninitializedOffset = 0;
        PCSX::Slice data;
        std::list<PsyqRelocation> relocations;
    };
    struct Symbol : public SymbolHashTable::Node {
        enum class SymbolType {
            EXPORTED,
            IMPORTED,
            UNINITIALIZED,
        } symbolType;
        uint16_t sectionIndex;
        uint32_t offset;
        uint32_t size;
        std::string name;
    };
    void reset() {
        currentSection = 0xffff;
        gotProgramSeven = false;
        sections.destroyAll();
        symbols.destroyAll();
    }
    Section* getCurrentSection() {
        auto section = sections.find(currentSection);
        if (section == sections.end()) return nullptr;
        return &*section;
    }
    uint16_t currentSection = 0xffff;
    bool gotProgramSeven = false;
    SectionHashTable sections;
    SymbolHashTable symbols;
};

static PsyqLnkFile s_currentLnkFile;

static std::string readPsyqString(PCSX::File* file) { return file->readString(file->byte()); }

static std::unique_ptr<PsyqExpression> readExpression(PCSX::File* file, int level = 0) {
    std::unique_ptr<PsyqExpression> ret = std::make_unique<PsyqExpression>();
    uint8_t exprOp = file->read<uint8_t>();
    ret->type = PsyqExprOpcode(exprOp);
    vprint("    ");
    for (int i = 0; i < level; i++) vprint("  ");
    switch (exprOp) {
        case (uint8_t)PsyqExprOpcode::VALUE: {
            uint32_t value = file->read<uint32_t>();
            vprint("Value: {:08x}\n", value);
            ret->value = value;
            break;
        }
        case (uint8_t)PsyqExprOpcode::IMPORT: {
            uint16_t import = file->read<uint16_t>();
            vprint("Import: {}\n", import);
            ret->import = import;
            break;
        }
        case (uint8_t)PsyqExprOpcode::SECTION_BASE: {
            uint16_t sectionIndex = file->read<uint16_t>();
            vprint("Base of section {}\n", sectionIndex);
            ret->sectionIndex = sectionIndex;
            break;
        }
        case (uint8_t)PsyqExprOpcode::SECTION_START: {
            uint16_t sectionIndex = file->read<uint16_t>();
            vprint("Start of section {}\n", sectionIndex);
            ret->sectionIndex = sectionIndex;
            break;
        }
        case (uint8_t)PsyqExprOpcode::SECTION_END: {
            uint16_t sectionIndex = file->read<uint16_t>();
            vprint("End of section {}\n", sectionIndex);
            ret->sectionIndex = sectionIndex;
            break;
        }
        case (uint8_t)PsyqExprOpcode::ADD: {
            vprint("Add:\n");
            ret->right = readExpression(file, level + 1);
            ret->left = readExpression(file, level + 1);
            if (!ret->left || !ret->right) {
                return nullptr;
            }
            break;
        }
        case (uint8_t)PsyqExprOpcode::SUB: {
            vprint("Sub:\n");
            ret->right = readExpression(file, level + 1);
            ret->left = readExpression(file, level + 1);
            if (!ret->left || !ret->right) {
                return nullptr;
            }
            break;
        }
        case (uint8_t)PsyqExprOpcode::DIV: {
            vprint("Div:\n");
            ret->right = readExpression(file, level + 1);
            ret->left = readExpression(file, level + 1);
            if (!ret->left || !ret->right) {
                return nullptr;
            }
            break;
        }
        default: {
            fmt::print("Unknown expression type {}\n", exprOp);
            return nullptr;
        }
    }
    return ret;
}

static int parsePsyq(PCSX::File* file) {
    vprint(":: Reading signature.\n");
    std::string signature = file->readString(3);
    if (signature != "LNK") {
        fmt::print("Wrong signature: {}\n", signature);
        return -1;
    }
    vprint(" --> Signature ok.\n");

    vprint(":: Reading version: ");
    uint8_t version = file->byte();
    vprint("{}\n", version);
    if (version != 2) {
        fmt::print("Unknown version {}\n", version);
        return -1;
    }

    vprint(":: Parsing file...\n");
    while (!file->eof()) {
        uint8_t opcode = file->byte();
        vprint("  :: Read opcode {} --> ", opcode);
        switch (opcode) {
            case (uint8_t)PsyqOpcode::END: {
                vprint("EOF\n");
                return 0;
            }
            case (uint8_t)PsyqOpcode::BYTES: {
                uint16_t size = file->read<uint16_t>();
                vprint("Bytes ({:04x})\n", size);
                PCSX::Slice slice = file->read(size);
                std::string hex = slice.toHexString();
                vprint("{}\n", hex.c_str());
                auto section = s_currentLnkFile.getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", s_currentLnkFile.currentSection);
                    return -1;
                }
                if (section->zeroes) {
                    void* ptr = calloc(section->zeroes, 1);
                    PCSX::Slice zeroes;
                    zeroes.acquire(ptr, section->zeroes);
                    section->zeroes = 0;
                    section->data.concatenate(zeroes);
                }
                section->data.concatenate(slice);
                break;
            }
            case (uint8_t)PsyqOpcode::SWITCH: {
                uint16_t sectionIndex = file->read<uint16_t>();
                vprint("Switch to section {}\n", sectionIndex);
                s_currentLnkFile.currentSection = sectionIndex;
                break;
            }
            case (uint8_t)PsyqOpcode::ZEROES: {
                uint32_t size = file->read<uint32_t>();
                vprint("Zeroes ({:04x})\n", size);
                auto section = s_currentLnkFile.getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", s_currentLnkFile.currentSection);
                    return -1;
                }
                section->zeroes += size;
                break;
            }
            case (uint8_t)PsyqOpcode::RELOCATION: {
                uint8_t relocType = file->read<uint8_t>();
                vprint("Relocation {} ", relocType);
                switch (relocType) {
                    case (uint8_t)PsyqRelocType::REL32: {
                        vprint("(REL32), ");
                        break;
                    }
                    case (uint8_t)PsyqRelocType::REL26: {
                        vprint("(REL26), ");
                        break;
                    }
                    case (uint8_t)PsyqRelocType::HI16: {
                        vprint("(HI16), ");
                        break;
                    }
                    case (uint8_t)PsyqRelocType::LO16: {
                        vprint("(LO16), ");
                        break;
                    }
                    default: {
                        fmt::print("Unknown relocation type {}\n", relocType);
                        return -1;
                    }
                }
                uint16_t offset = file->read<uint16_t>();
                vprint("offset {:04x}, expression: \n", offset);
                std::unique_ptr<PsyqExpression> expression = readExpression(file);
                if (!expression) return -1;
                auto section = s_currentLnkFile.getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", s_currentLnkFile.currentSection);
                    return -1;
                }
                section->relocations.emplace_back(
                    PsyqRelocation{PsyqRelocType(relocType), offset, std::move(expression)});
                break;
            }
            case (uint8_t)PsyqOpcode::EXPORTED_SYMBOL: {
                uint16_t symbolIndex = file->read<uint16_t>();
                uint16_t sectionIndex = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                vprint("Export: id {}, section {}, offset {:08x}, name {}\n", symbolIndex, sectionIndex, offset, name);
                PsyqLnkFile::Symbol* symbol = new PsyqLnkFile::Symbol();
                symbol->symbolType = PsyqLnkFile::Symbol::SymbolType::EXPORTED;
                symbol->sectionIndex = sectionIndex;
                symbol->offset = offset;
                symbol->name = name;
                s_currentLnkFile.symbols.insert(symbolIndex, symbol);
                break;
            }
            case (uint8_t)PsyqOpcode::IMPORTED_SYMBOL: {
                uint16_t symbolIndex = file->read<uint16_t>();
                std::string name = readPsyqString(file);
                vprint("Import: id {}, name {}\n", symbolIndex, name);
                PsyqLnkFile::Symbol* symbol = new PsyqLnkFile::Symbol();
                symbol->symbolType = PsyqLnkFile::Symbol::SymbolType::IMPORTED;
                symbol->name = name;
                s_currentLnkFile.symbols.insert(symbolIndex, symbol);
                break;
            }
            case (uint8_t)PsyqOpcode::SECTION: {
                uint16_t sectionIndex = file->read<uint16_t>();
                uint16_t group = file->read<uint16_t>();
                uint8_t alignment = file->read<uint8_t>();
                std::string name = readPsyqString(file);
                vprint("Section: id {}, group {}, alignment {}, name {}\n", sectionIndex, group, alignment, name);
                PsyqLnkFile::Section* section = new PsyqLnkFile::Section();
                section->group = group;
                section->alignment = alignment;
                section->name = name;
                s_currentLnkFile.sections.insert(sectionIndex, section);
                break;
            }
            case (uint8_t)PsyqOpcode::PROGRAMTYPE: {
                uint8_t type = file->read<uint8_t>();
                vprint("Program type {}\n", type);
                if (type != 7) {
                    fmt::print("Unknown program type {}\n", type);
                    return -1;
                }
                if (s_currentLnkFile.gotProgramSeven) {
                    fmt::print("Already got program type.\n");
                    return -1;
                }
                s_currentLnkFile.gotProgramSeven = true;
                break;
            }
            case (uint8_t)PsyqOpcode::UNINITIALIZED: {
                uint16_t symbolIndex = file->read<uint16_t>();
                uint16_t sectionIndex = file->read<uint16_t>();
                uint32_t size = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                vprint("Uninitilized: id {}, section {}, size {:08x}, name {}\n", symbolIndex, sectionIndex, size,
                       name);
                PsyqLnkFile::Symbol* symbol = new PsyqLnkFile::Symbol();
                symbol->symbolType = PsyqLnkFile::Symbol::SymbolType::UNINITIALIZED;
                symbol->sectionIndex = sectionIndex;
                symbol->size = size;
                symbol->name = name;
                auto section = s_currentLnkFile.sections.find(sectionIndex);
                if (section == s_currentLnkFile.sections.end()) {
                    fmt::print("Section {} not found.\n", sectionIndex);
                    return -1;
                }
                symbol->offset = section->uninitializedOffset;
                section->uninitializedOffset += size;
                s_currentLnkFile.symbols.insert(symbolIndex, symbol);
                break;
            }
            default: {
                fmt::print("Unknown opcode {}.\n", opcode);
                return -1;
            }
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    flags::args args(argc, argv);
    auto output = args.get<std::string>("o");

    auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool noInput = inputs.size() == 0;
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    if (asksForHelp || noInput || (hasOutput && !oneInput)) {
        fmt::print(R"(
Usage: {} input.obj [input2.obj...] [-h] [-v] [-d] [-o output.o]
  input.obj      mandatory: specify the input psyq LNK object file.
  -h             displays this help information and exit.
  -v             turn on verbose mode for the parser.
  -d             dump the parsed input file.
  -o output.o    tries to dump the parsed psyq LNK file into an ELF file;
                 can only work with a single input file.
)",
                   argv[0]);
        return -1;
    }

    s_verbose = args.get<bool>("v").value_or(false);

    int ret = 0;

    for (auto& input : inputs) {
        PCSX::File* file = new PCSX::File(input);
        if (file->failed()) {
            fmt::print("Unable to open file: {}\n", input);
            ret = -1;
        } else {
            if (parsePsyq(file) != 0) ret = -1;
        }
        delete file;
        s_currentLnkFile.reset();
    }

    return ret;
}
