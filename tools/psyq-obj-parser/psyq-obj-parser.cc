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

#include <assert.h>

#include <list>
#include <map>
#include <string>
#include <string_view>

#include "elfio/elfio.hpp"
#include "flags.h"
#include "fmt/format.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/djbhash.h"
#include "support/file.h"
#include "support/hashtable.h"
#include "support/slice.h"
#include "support/windowswrapper.h"

#define SHF_MIPS_GPREL 0x10000000

#define vprint(...) \
    if (verbose) fmt::print(__VA_ARGS__)

/* The constants from the psyq link files */
enum class PsyqOpcode : uint8_t {
    END = 0,
    BYTES = 2,
    SWITCH = 6,
    ZEROES = 8,
    RELOCATION = 10,
    EXPORTED_SYMBOL = 12,
    IMPORTED_SYMBOL = 14,
    SECTION = 16,
    LOCAL_SYMBOL = 18,
    FILENAME = 28,
    PROGRAMTYPE = 46,
    UNINITIALIZED = 48,
    INC_SLD_LINENUM = 50,
    INC_SLD_LINENUM_BY_BYTE = 52,
    SET_SLD_LINENUM = 56,
    SET_SLD_LINENUM_FILE = 58,
    END_SLD = 60,
    FUNCTION = 74,
    FUNCTION_END = 76,
    SECTION_DEF = 82,
    SECTION_DEF2 = 84,
};

enum class PsyqRelocType : uint8_t {
    REL32 = 16,
    REL26 = 74,
    HI16 = 82,
    LO16 = 84,
    GPREL16 = 100,
};

enum class PsyqExprOpcode : uint8_t {
    VALUE = 0,
    SYMBOL = 2,
    SECTION_BASE = 4,
    SECTION_START = 12,
    SECTION_END = 22,
    ADD = 44,
    SUB = 46,
    DIV = 50,
};

/* Constants to indicate which rewrite pass we're at */
enum class ElfRelocationPass {
    PASS1,
    PASS2,
};

/* ELFIO isn't providing those */
enum class elf_mips_reloc_type : unsigned char {
    R_MIPS_NONE = 0,
    R_MIPS_16,
    R_MIPS_32,
    R_MIPS_REL32,
    R_MIPS_26,
    R_MIPS_HI16,
    R_MIPS_LO16,
    R_MIPS_GPREL16,
    R_MIPS_LITERAL,
    R_MIPS_GOT16,
    R_MIPS_PC16,
    R_MIPS_CALL16,
    R_MIPS_GPREL32,
};

/* The main structure to hold a psyq LNK (.OBJ) file */
struct PsyqLnkFile {
    struct Section;
    struct Symbol;
    struct Relocation;
    struct Expression;

    /* The main parser entry point; will return nullptr on error */
    static std::unique_ptr<PsyqLnkFile> parse(PCSX::IO<PCSX::File> file, bool verbose);
    static std::string readPsyqString(PCSX::IO<PCSX::File> file) { return file->readString(file->byte()); }

    /* Our list of sections and symbols will be keyed by their id from the LNK file */
    typedef PCSX::Intrusive::HashTable<uint16_t, Section> SectionHashTable;
    typedef PCSX::Intrusive::HashTable<uint16_t, Symbol> SymbolHashTable;

    struct Section : public SectionHashTable::Node {
        uint16_t group;
        uint8_t alignment;
        std::string name;
        uint32_t zeroes = 0;
        uint32_t uninitializedOffset = 0;
        PCSX::Slice data;
        std::list<Relocation> relocations;
        uint32_t getFullSize() { return data.size() + zeroes + uninitializedOffset; }
        uint32_t pointer = 0;

        ELFIO::section* section = nullptr;
        ELFIO::section* rel_sec = nullptr;

        void display(PsyqLnkFile* lnk);
        void displayRelocs(PsyqLnkFile* lnk);
        bool isBss() { return (name == ".bss") || (name == ".sbss"); }
        bool isText() { return (name == ".text"); }
        bool generateElfSection(PsyqLnkFile* psyq, ELFIO::elfio& writer);
        bool generateElfRelocations(ElfRelocationPass pass, const std::string& prefix, PsyqLnkFile* psyq,
                                    ELFIO::elfio& writer, ELFIO::Elf_Word symbolSectionIndex,
                                    ELFIO::string_section_accessor& stra, ELFIO::symbol_section_accessor& syma);
    };
    struct Symbol : public SymbolHashTable::Node {
        enum class Type {
            LOCAL,
            EXPORTED,
            IMPORTED,
            UNINITIALIZED,
        } symbolType;
        uint16_t sectionIndex;
        uint32_t offset = 0;
        uint32_t size = 0;
        std::string name;
        ELFIO::Elf_Word elfSym;
        uint32_t getOffset(PsyqLnkFile* psyq) const {
            if (symbolType == Type::UNINITIALIZED) {
                auto section = psyq->sections.find(sectionIndex);
                assert(section != psyq->sections.end());
                return section->data.size() + section->zeroes + offset;
            } else {
                return offset;
            }
        }
        void display(PsyqLnkFile* lnk);
        bool generateElfSymbol(PsyqLnkFile* psyq, ELFIO::string_section_accessor& stra,
                               ELFIO::symbol_section_accessor& syma);
    };
    struct Relocation {
        PsyqRelocType type;
        uint32_t offset;
        std::unique_ptr<Expression> expression;
        void display(PsyqLnkFile* lnk, PsyqLnkFile::Section* sec);
        bool generateElf(ElfRelocationPass pass, const std::string& prefix, PsyqLnkFile* psyq,
                         PsyqLnkFile::Section* section, ELFIO::elfio& writer, ELFIO::string_section_accessor& stra,
                         ELFIO::symbol_section_accessor& syma, ELFIO::relocation_section_accessor& rela);
    };
    struct Expression {
        PsyqExprOpcode type;
        std::unique_ptr<Expression> left = nullptr;
        std::unique_ptr<Expression> right = nullptr;
        uint32_t value;
        uint16_t symbolIndex;
        uint16_t sectionIndex;
        static std::unique_ptr<Expression> parse(PCSX::IO<PCSX::File> file, bool verbose, int level = 0);
        void display(PsyqLnkFile* lnk, bool top = false);
    };

    SectionHashTable sections;
    SymbolHashTable symbols;
    int localIndex = 0;

    /* There's some state we need to maintain during parsing */
    Section* getCurrentSection() {
        auto section = sections.find(currentSection);
        if (section == sections.end()) return nullptr;
        return &*section;
    }
    uint16_t currentSection = 0xffff;
    bool gotProgramSeven = false;

    /* And there's some state we need to maintain during elf conversion */
    std::map<std::string, ELFIO::Elf_Word> localElfSymbols;
    std::string elfConversionError;
    Relocation* twoPartsReloc = nullptr;
    uint32_t twoPartsRelocAddend;
    uint16_t twoPartsRelocSymbol;

    void display();
    bool writeElf(const std::string& prefix, const std::string& out, bool abiNone);
    template <typename... Args>
    inline void setElfConversionError(std::string_view formatStr, Args&&... args) {
        elfConversionError = fmt::format(fmt::runtime(formatStr), args...);
#ifdef _WIN32
        if (IsDebuggerPresent()) __debugbreak();
#endif
    }
};

/* The psyq LNK parser code */
std::unique_ptr<PsyqLnkFile> PsyqLnkFile::parse(PCSX::IO<PCSX::File> file, bool verbose) {
    std::unique_ptr<PsyqLnkFile> ret = std::make_unique<PsyqLnkFile>();
    vprint(":: Reading signature.\n");
    std::string signature = file->readString(3);
    if (signature != "LNK") {
        fmt::print(stderr, "Wrong signature: {}\n", signature);
        return nullptr;
    }
    vprint(" --> Signature ok.\n");

    vprint(":: Reading version: ");
    uint8_t version = file->byte();
    vprint("{}\n", version);
    if (version != 2) {
        fmt::print(stderr, "Unknown version {}\n", version);
        return nullptr;
    }

    vprint(":: Parsing file...\n");
    while (!file->eof()) {
        uint8_t opcode = file->byte();
        vprint("  :: Read opcode {} --> ", opcode);
        switch (opcode) {
            case (uint8_t)PsyqOpcode::END: {
                vprint("EOF\n");
                return ret;
            }
            case (uint8_t)PsyqOpcode::BYTES: {
                uint16_t size = file->read<uint16_t>();
                vprint("Bytes ({:04x})\n", size);
                PCSX::Slice slice = file->read(size);
                std::string hex = slice.toHexString();
                vprint("{}\n", hex.c_str());
                auto section = ret->getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", ret->currentSection);
                    return nullptr;
                }
                section->pointer = section->getFullSize();
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
                ret->currentSection = sectionIndex;
                break;
            }
            case (uint8_t)PsyqOpcode::ZEROES: {
                uint32_t size = file->read<uint32_t>();
                vprint("Zeroes ({:04x})\n", size);
                auto section = ret->getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", ret->currentSection);
                    return nullptr;
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
                    case (uint8_t)PsyqRelocType::GPREL16: {
                        vprint("(GPREL16), ");
                        break;
                    }
                    default: {
                        fmt::print("Unknown relocation type {}\n", relocType);
                        return nullptr;
                    }
                }
                uint16_t offset = file->read<uint16_t>();
                auto section = ret->getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", ret->currentSection);
                    return nullptr;
                }
                vprint("offset {:04x}+{:08x}, expression: \n", offset, section->pointer);
                std::unique_ptr<Expression> expression = Expression::parse(file, verbose);
                if (!expression) return nullptr;
                section->relocations.emplace_back(
                    Relocation{PsyqRelocType(relocType), offset + section->pointer, std::move(expression)});
                break;
            }
            case (uint8_t)PsyqOpcode::EXPORTED_SYMBOL: {
                uint16_t symbolIndex = file->read<uint16_t>();
                uint16_t sectionIndex = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                vprint("Export: id {}, section {}, offset {:08x}, name {}\n", symbolIndex, sectionIndex, offset, name);
                Symbol* symbol = new Symbol();
                symbol->symbolType = Symbol::Type::EXPORTED;
                symbol->sectionIndex = sectionIndex;
                symbol->offset = offset;
                symbol->name = name;
                ret->symbols.insert(symbolIndex, symbol);
                break;
            }
            case (uint8_t)PsyqOpcode::IMPORTED_SYMBOL: {
                uint16_t symbolIndex = file->read<uint16_t>();
                std::string name = readPsyqString(file);
                vprint("Import: id {}, name {}\n", symbolIndex, name);
                Symbol* symbol = new Symbol();
                symbol->symbolType = Symbol::Type::IMPORTED;
                symbol->name = name;
                ret->symbols.insert(symbolIndex, symbol);
                break;
            }
            case (uint8_t)PsyqOpcode::SECTION: {
                uint16_t sectionIndex = file->read<uint16_t>();
                uint16_t group = file->read<uint16_t>();
                uint8_t alignment = file->read<uint8_t>();
                std::string name = readPsyqString(file);
                vprint("Section: id {}, group {}, alignment {}, name {}\n", sectionIndex, group, alignment, name);
                Section* section = new Section();
                section->group = group;
                section->alignment = alignment;
                section->name = name;
                ret->sections.insert(sectionIndex, section);
                if ((alignment - 1) & alignment) {
                    fmt::print(stderr, "Section alignment {} isn't a power of two.\n", alignment);
                    return nullptr;
                }
                break;
            }
            case (uint8_t)PsyqOpcode::LOCAL_SYMBOL: {
                uint16_t sectionIndex = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                vprint("Local: section {}, offset {}, name {}\n", sectionIndex, offset, name);
                Symbol* symbol = new Symbol();
                symbol->symbolType = Symbol::Type::LOCAL;
                symbol->sectionIndex = sectionIndex;
                symbol->offset = offset;
                symbol->name = name;
                ret->symbols.insert(--ret->localIndex, symbol);
                break;
            }
            case (uint8_t)PsyqOpcode::FILENAME: {
                uint16_t index = file->read<uint16_t>();
                std::string name = readPsyqString(file);
                vprint("File {}: {}\n", index, name);
                break;
            }
            case (uint8_t)PsyqOpcode::PROGRAMTYPE: {
                uint8_t type = file->read<uint8_t>();
                vprint("Program type {}\n", type);
                if (type != 7) {
                    fmt::print(stderr, "Unknown program type {}.\n", type);
                    return nullptr;
                }
                if (ret->gotProgramSeven) {
                    fmt::print(stderr, "Already got program type.\n");
                    return nullptr;
                }
                ret->gotProgramSeven = true;
                break;
            }
            case (uint8_t)PsyqOpcode::UNINITIALIZED: {
                uint16_t symbolIndex = file->read<uint16_t>();
                uint16_t sectionIndex = file->read<uint16_t>();
                uint32_t size = file->read<uint32_t>();
                std::string name = readPsyqString(file);

                Symbol* symbol = new Symbol();
                symbol->symbolType = Symbol::Type::UNINITIALIZED;
                symbol->sectionIndex = sectionIndex;
                symbol->size = size;
                symbol->name = name;
                auto section = ret->sections.find(sectionIndex);
                if (section == ret->sections.end()) {
                    fmt::print(stderr, "Section {} not found for {}.\n", sectionIndex, name);
                    return nullptr;
                }

                // Each entry is aligned to the size of the type after testing the output of mixed .bss and sbss with
                // psyq GCC 2.7.2 this works the same way as modern GCC.
                auto sizeToUse = symbol->size;
                if (sizeToUse > section->alignment) {
                    sizeToUse = section->alignment;
                }
                auto align = sizeToUse - 1;
                section->uninitializedOffset += align;
                section->uninitializedOffset &= ~align;
                symbol->offset = section->uninitializedOffset;

                vprint("Uninitialized: id {}, section {}, offset {:08x}, size {:08x}, name {}\n", symbolIndex,
                       sectionIndex, symbol->offset, size, name);

                section->uninitializedOffset += size;
                ret->symbols.insert(symbolIndex, symbol);
                break;
            }
            case (uint8_t)PsyqOpcode::INC_SLD_LINENUM: {
                uint16_t offset = file->read<uint16_t>();
                vprint("INC_SLD_LINENUM offset {}\n", offset);

                break;
            }
            case (uint8_t)PsyqOpcode::INC_SLD_LINENUM_BY_BYTE: {
                uint16_t offset = file->read<uint16_t>();
                uint8_t _byte = file->read<uint8_t>();
                vprint("INC_SLD_LINENUM_BY_BYTE offset {}, _byte {}\n", offset, _byte);

                break;
            }
            case (uint8_t)PsyqOpcode::SET_SLD_LINENUM: {
                uint16_t offset = file->read<uint16_t>();
                uint32_t lineNum = file->read<uint32_t>();
                vprint("SET_SLD_LINENUM lineNum {}, offset {}\n", lineNum, offset);
                break;
            }
            case (uint8_t)PsyqOpcode::SET_SLD_LINENUM_FILE: {
                uint16_t offset = file->read<uint16_t>();
                uint32_t lineNum = file->read<uint32_t>();
                uint16_t _file = file->read<uint16_t>();
                vprint("SET_SLD_LINENUM_FILE lineNum {}, offset {}, _file {}\n", lineNum, offset, _file);
                break;
            }
            case (uint8_t)PsyqOpcode::END_SLD: {
                // 2 bytes of nothing
                uint16_t zero = file->read<uint16_t>();
                assert(zero == 0);
                vprint("END_SLD\n");
                break;
            }
            case (uint8_t)PsyqOpcode::FUNCTION: {
                uint16_t section = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                uint16_t _file = file->read<uint16_t>();
                uint32_t startLine = file->read<uint32_t>();
                uint16_t frameReg = file->read<uint16_t>();
                uint32_t frameSize = file->read<uint32_t>();
                uint16_t retnPcReg = file->read<uint16_t>();
                uint32_t mask = file->read<uint32_t>();
                uint32_t maskOffset = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                vprint(
                    "FUNCTION: section {}, offset {}, _file {}, startLine {}, frameReg {}, frameSize {}, retnPcReg {}, "
                    "mask {}, maskOffset {}, name {}\n",
                    section, offset, _file, startLine, frameReg, frameSize, retnPcReg, mask, maskOffset, name);
                break;
            }
            case (uint8_t)PsyqOpcode::FUNCTION_END: {
                uint16_t section = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                uint32_t endLine = file->read<uint32_t>();
                vprint("FUNCTION_END: section {}, offset {}, endLine {}\n", section, offset, endLine);
                break;
            }
            case (uint8_t)PsyqOpcode::SECTION_DEF: {
                uint16_t section = file->read<uint16_t>();
                uint32_t value = file->read<uint32_t>();
                uint16_t _class = file->read<uint16_t>();
                uint16_t type = file->read<uint16_t>();
                uint32_t size = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                vprint("SECTION_DEF: section {}, value {}, _class {}, type {}, size {}\n", section, value, _class, type,
                       size);
                break;
            }
            case (uint8_t)PsyqOpcode::SECTION_DEF2: {
                uint16_t section = file->read<uint16_t>();
                uint32_t value = file->read<uint32_t>();
                uint16_t _class = file->read<uint16_t>();
                uint16_t type = file->read<uint16_t>();
                uint32_t size = file->read<uint32_t>();

                uint16_t dims = file->read<uint16_t>();
                while (dims-- > 0) {
                    // ignore for now
                    uint16_t dim = file->read<uint16_t>();
                }

                std::string tag = readPsyqString(file);
                std::string name = readPsyqString(file);
                vprint("SECTION_DEF2: section {}, value {}, _class {}, type {}, size {}, dims {}, tag {}, name {}\n",
                       section, value, _class, type, size, dims, tag, name);
                break;
            }
            default: {
                fmt::print(stderr, "Unknown opcode {}.\n", opcode);
                return nullptr;
            }
        }
    }

    fmt::print(stderr, "Got actual end of file before EOF command.\n");

    return nullptr;
}

std::unique_ptr<PsyqLnkFile::Expression> PsyqLnkFile::Expression::parse(PCSX::IO<PCSX::File> file, bool verbose,
                                                                        int level) {
    std::unique_ptr<PsyqLnkFile::Expression> ret = std::make_unique<PsyqLnkFile::Expression>();
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
        case (uint8_t)PsyqExprOpcode::SYMBOL: {
            uint16_t import = file->read<uint16_t>();
            vprint("Import: {}\n", import);
            ret->symbolIndex = import;
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
            ret->right = parse(file, verbose, level + 1);
            ret->left = parse(file, verbose, level + 1);
            if ((ret->right->type == PsyqExprOpcode::ADD) && (ret->left->type == PsyqExprOpcode::VALUE)) {
                auto addend = ret->left->value;
                if (ret->right->right->type == PsyqExprOpcode::VALUE) {
                    ret->right->right->value += addend;
                    return std::move(ret->right);
                } else if (ret->right->left->type == PsyqExprOpcode::VALUE) {
                    ret->right->left->value += addend;
                    return std::move(ret->right);
                }
            } else if ((ret->left->type == PsyqExprOpcode::ADD) && (ret->right->type == PsyqExprOpcode::VALUE)) {
                auto addend = ret->right->value;
                if (ret->left->right->type == PsyqExprOpcode::VALUE) {
                    ret->left->right->value += addend;
                    return std::move(ret->left);
                } else if (ret->left->left->type == PsyqExprOpcode::VALUE) {
                    ret->left->left->value += addend;
                    return std::move(ret->left);
                }
            }
            if (!ret->left || !ret->right) {
                return nullptr;
            }
            break;
        }
        case (uint8_t)PsyqExprOpcode::SUB: {
            vprint("Sub:\n");
            ret->right = parse(file, verbose, level + 1);
            ret->left = parse(file, verbose, level + 1);
            if (!ret->left || !ret->right) {
                return nullptr;
            }
            break;
        }
        case (uint8_t)PsyqExprOpcode::DIV: {
            vprint("Div:\n");
            ret->right = parse(file, verbose, level + 1);
            ret->left = parse(file, verbose, level + 1);
            if (!ret->left || !ret->right) {
                return nullptr;
            }
            break;
        }
        default: {
            fmt::print(stderr, "Unknown expression type {}\n", exprOp);
            return nullptr;
        }
    }
    return ret;
}

/* The display functions */
void PsyqLnkFile::display() {
    fmt::print("  :: Symbols\n\n");
    fmt::print("    {:^4}   {:^6}   {:^6}  {:^12}   {:^8}   {:^8}   {}\n", "indx", "type", "sectn", "", "offset",
               "size", "name");
    fmt::print("    -----------------------------------------------------------------\n");
    for (auto& symbol : symbols) {
        symbol.display(this);
    }
    fmt::print("\n\n\n  :: Sections\n\n");
    fmt::print("    {:4}   {:4}   {:8}   {:8}   {:8}   {:8}   {:8}   {}\n", "indx", "grp", "alignmnt", "size", "data",
               "zeroes", "alloc", "name");
    fmt::print("    -------------------------------------------------------------------------\n");
    for (auto& section : sections) {
        section.display(this);
    }
    fmt::print("\n\n\n  :: Relocations\n\n");
    fmt::print("    {:8}   {:>12}::{:8}  {}\n", "type", "section", "offset", "expression");
    fmt::print("    ------------------------------------------\n");
    for (auto& section : sections) {
        section.displayRelocs(this);
    }
}

void PsyqLnkFile::Symbol::display(PsyqLnkFile* lnk) {
    if (symbolType == Type::EXPORTED) {
        auto section = lnk->sections.find(sectionIndex);
        if (section == lnk->sections.end()) {
            fmt::print("** BROKEN SYMBOL AT INDEX {:04x} **\n", getKey());
        } else {
            fmt::print("    {:04x}   {:6}   ({:04x})  {:12}   {:08x}   {:8}   {}\n", getKey(), "EXPORT", sectionIndex,
                       section->name, getOffset(lnk), "", name);
        }
    } else if (symbolType == Type::IMPORTED) {
        fmt::print("    {:04x}   {:6}   {:6}  {:12}   {:8}   {:8}   {}\n", getKey(), "IMPORT", "", "", "", "", name);
    } else {
        auto section = lnk->sections.find(sectionIndex);
        if (section == lnk->sections.end()) {
            fmt::print("** BROKEN SYMBOL AT INDEX {:04x} **\n", getKey());
        } else {
            fmt::print("    {:04x}   {:6}   ({:04x})  {:12}  ({:08x})  {:08x}   {}\n", getKey(), "UNDEFN", sectionIndex,
                       section->name, getOffset(lnk), size, name);
        }
    }
}

void PsyqLnkFile::Section::display(PsyqLnkFile* lnk) {
    fmt::print("    {:04x}   {:04x}   {:8}   {:08x}   {:08x}   {:08x}   {:08x}   {}\n", getKey(), group, alignment,
               getFullSize(), data.size(), zeroes, uninitializedOffset, name);
}

void PsyqLnkFile::Section::displayRelocs(PsyqLnkFile* lnk) {
    for (auto& reloc : relocations) {
        reloc.display(lnk, this);
        fmt::print("\n");
    }
}

void PsyqLnkFile::Relocation::display(PsyqLnkFile* lnk, PsyqLnkFile::Section* sec) {
    static const std::map<PsyqRelocType, std::string> typeStr = {
        {PsyqRelocType::REL32, "REL32"}, {PsyqRelocType::REL26, "REL26"},     {PsyqRelocType::HI16, "HI16"},
        {PsyqRelocType::LO16, "LO16"},   {PsyqRelocType::GPREL16, "GPREL16"},
    };
    fmt::print("    {:8}   {:>12}::{:08x}  ", typeStr.find(type)->second, sec->name, offset);
    expression->display(lnk, true);
}

void PsyqLnkFile::Expression::display(PsyqLnkFile* lnk, bool top) {
    switch (type) {
        case PsyqExprOpcode::VALUE: {
            fmt::print("{}", value);
            break;
        }
        case PsyqExprOpcode::SYMBOL: {
            auto symbol = lnk->symbols.find(symbolIndex);
            fmt::print("{}", symbol == lnk->symbols.end() ? "**ERR**" : symbol->name);
            break;
        }
        case PsyqExprOpcode::SECTION_BASE: {
            auto section = lnk->sections.find(sectionIndex);
            fmt::print("{}__base", section == lnk->sections.end() ? "**ERR**" : section->name);
            break;
        }
        case PsyqExprOpcode::SECTION_START: {
            auto section = lnk->sections.find(sectionIndex);
            fmt::print("{}__start", section == lnk->sections.end() ? "**ERR**" : section->name);
            break;
        }
        case PsyqExprOpcode::SECTION_END: {
            auto section = lnk->sections.find(sectionIndex);
            fmt::print("{}__end", section == lnk->sections.end() ? "**ERR**" : section->name);
            break;
        }
        case PsyqExprOpcode::ADD: {
            if (left->type == PsyqExprOpcode::VALUE) {
                if (left->value == 0) {
                    right->display(lnk);
                } else {
                    if (!top) fmt::print("(");
                    right->display(lnk);
                    fmt::print(" + ");
                    left->display(lnk);
                    if (!top) fmt::print(")");
                }
            } else {
                if (!top) fmt::print("(");
                left->display(lnk);
                fmt::print(" + ");
                right->display(lnk);
                if (!top) fmt::print(")");
            }
            break;
        }
        case PsyqExprOpcode::SUB: {
            if (!top) fmt::print("(");
            left->display(lnk);
            fmt::print(" - ");
            right->display(lnk);
            if (!top) fmt::print(")");
            break;
        }
        case PsyqExprOpcode::DIV: {
            if (!top) fmt::print("(");
            left->display(lnk);
            fmt::print(" / ");
            right->display(lnk);
            if (!top) fmt::print(")");
            break;
        }
    }
}

/* The ELF writer code */
bool PsyqLnkFile::writeElf(const std::string& prefix, const std::string& out, bool abiNone) {
    ELFIO::elfio writer;
    writer.create(ELFCLASS32, ELFDATA2LSB);
    writer.set_os_abi(abiNone ? ELFOSABI_NONE : ELFOSABI_LINUX);
    writer.set_type(ET_REL);
    writer.set_machine(EM_MIPS);
    writer.set_flags(0x1000);  // ?!

    fmt::print("  :: Generating sections\n");
    for (auto& section : sections) {
        bool success = section.generateElfSection(this, writer);
        if (!success) return false;
    }

    ELFIO::section* str_sec = writer.sections.add(".strtab");
    str_sec->set_type(SHT_STRTAB);
    ELFIO::string_section_accessor stra(str_sec);
    ELFIO::section* sym_sec = writer.sections.add(".symtab");
    sym_sec->set_type(SHT_SYMTAB);
    sym_sec->set_addr_align(0x4);
    sym_sec->set_entry_size(writer.get_default_entry_size(SHT_SYMTAB));
    sym_sec->set_link(str_sec->get_index());
    ELFIO::symbol_section_accessor syma(writer, sym_sec);

    syma.add_symbol(stra, out.c_str(), 0, STB_LOCAL, STT_FILE, 0, SHN_ABS);

    fmt::print("  :: Generating relocations - pass 1, local only\n");
    for (auto& section : sections) {
        bool success = section.generateElfRelocations(ElfRelocationPass::PASS1, prefix, this, writer,
                                                      sym_sec->get_index(), stra, syma);
        if (!success) return false;
    }

    sym_sec->set_info(syma.get_symbols_num());

    fmt::print("  :: Generating symbols\n");
    for (auto& symbol : symbols) {
        bool success = symbol.generateElfSymbol(this, stra, syma);
        if (!success) return false;
    }

    fmt::print("  :: Generating relocations - pass 2, globals only\n");
    for (auto& section : sections) {
        bool success = section.generateElfRelocations(ElfRelocationPass::PASS2, prefix, this, writer,
                                                      sym_sec->get_index(), stra, syma);
        if (!success) return false;
    }

    ELFIO::section* note = writer.sections.add(".note");
    note->set_type(SHT_NOTE);

    ELFIO::note_section_accessor noteWriter(writer, note);
    noteWriter.add_note(0x01, "psyq-obj-parser", 0, 0);
    noteWriter.add_note(0x01, "pcsx-redux project", 0, 0);
    noteWriter.add_note(0x01, "https://github.com/grumpycoders/pcsx-redux", 0, 0);

    writer.save(out);
    return true;
}

bool PsyqLnkFile::Symbol::generateElfSymbol(PsyqLnkFile* psyq, ELFIO::string_section_accessor& stra,
                                            ELFIO::symbol_section_accessor& syma) {
    ELFIO::Elf_Half elfSectionIndex = 0;
    bool isText = false;

    fmt::print("    :: Generating symbol {}\n", name);
    if (symbolType != Type::IMPORTED) {
        auto section = psyq->sections.find(sectionIndex);
        if (section == psyq->sections.end()) {
            psyq->setElfConversionError("Couldn't find section index {} for symbol {} ('{}')", sectionIndex, getKey(),
                                        name);
            return false;
        }
        elfSectionIndex = section->section->get_index();
        isText = section->isText();
    }
    elfSym =
        syma.add_symbol(stra, name.c_str(), getOffset(psyq), size, symbolType == Type::LOCAL ? STB_LOCAL : STB_GLOBAL,
                        isText ? STT_FUNC : STT_NOTYPE, 0, elfSectionIndex);
    return true;
}

bool PsyqLnkFile::Section::generateElfSection(PsyqLnkFile* psyq, ELFIO::elfio& writer) {
    if (getFullSize() == 0) return true;
    fmt::print("    :: Generating section {}\n", name);
    static const std::map<std::string, ELFIO::Elf_Xword> flagsMap = {
        {".text", SHF_ALLOC | SHF_EXECINSTR}, {".rdata", SHF_ALLOC},
        {".data", SHF_ALLOC | SHF_WRITE},     {".sdata", SHF_ALLOC | SHF_WRITE | SHF_MIPS_GPREL},
        {".bss", SHF_ALLOC | SHF_WRITE},      {".sbss", SHF_ALLOC | SHF_WRITE | SHF_MIPS_GPREL},
    };
    auto flags = flagsMap.find(name);
    if (flags == flagsMap.end()) {
        psyq->setElfConversionError("Unknown section type '{}'", name);
        return false;
    }
    if (isBss() && data.size()) {
        psyq->setElfConversionError("Section {} looks like bss, but has data", name);
        return false;
    }
    section = writer.sections.add(name);
    section->set_type(isBss() ? SHT_NOBITS : SHT_PROGBITS);
    section->set_flags(flags->second);
    section->set_addr_align(alignment);
    if (isBss()) {
        section->set_size(getFullSize());
    } else {
        section->set_data((const char*)data.data(), ELFIO::Elf_Word(data.size()));
        ELFIO::Elf_Word z = zeroes + uninitializedOffset;
        if (z) {
            void* ptr = calloc(z, 1);
            section->append_data((char*)ptr, z);
            free(ptr);
        }
    }
    return true;
}

bool PsyqLnkFile::Section::generateElfRelocations(ElfRelocationPass pass, const std::string& prefix, PsyqLnkFile* psyq,
                                                  ELFIO::elfio& writer, ELFIO::Elf_Word symbolSectionIndex,
                                                  ELFIO::string_section_accessor& stra,
                                                  ELFIO::symbol_section_accessor& syma) {
    if (relocations.size() == 0) return true;
    if (pass == ElfRelocationPass::PASS1) {
        rel_sec = writer.sections.add(fmt::format(".rel{}", name));
        rel_sec->set_type(SHT_REL);
        rel_sec->set_info(section->get_index());
        rel_sec->set_addr_align(0x4);
        rel_sec->set_entry_size(writer.get_default_entry_size(SHT_REL));
        rel_sec->set_link(symbolSectionIndex);
    }
    ELFIO::relocation_section_accessor rela(writer, rel_sec);

    for (auto& relocation : relocations) {
        bool success = relocation.generateElf(pass, prefix, psyq, this, writer, stra, syma, rela);
        if (!success) return false;
    }
    if (psyq->twoPartsReloc) {
        psyq->setElfConversionError("Two parts relocation with only the first part");
        return false;
    }
    return true;
}

bool PsyqLnkFile::Relocation::generateElf(ElfRelocationPass pass, const std::string& prefix, PsyqLnkFile* psyq,
                                          PsyqLnkFile::Section* section, ELFIO::elfio& writer,
                                          ELFIO::string_section_accessor& stra, ELFIO::symbol_section_accessor& syma,
                                          ELFIO::relocation_section_accessor& rela) {
    fmt::print("    :: Generating relocation ");
    display(psyq, section);
    fmt::print("\n");
    struct SkippedDisplay {
        ~SkippedDisplay() {
            if (skipped) fmt::print("      :: Skipped for this pass\n");
        }
        bool skipped = false;
    } skipped;
    static const std::map<PsyqRelocType, elf_mips_reloc_type> typeMap = {
        {PsyqRelocType::REL32, elf_mips_reloc_type::R_MIPS_32},
        {PsyqRelocType::REL26, elf_mips_reloc_type::R_MIPS_26},
        {PsyqRelocType::HI16, elf_mips_reloc_type::R_MIPS_HI16},
        {PsyqRelocType::LO16, elf_mips_reloc_type::R_MIPS_LO16},
        {PsyqRelocType::GPREL16, elf_mips_reloc_type::R_MIPS_GPREL16},
    };
    auto simpleSymbolReloc = [&, this](Expression* expr, ELFIO::Elf_Word elfSym = 0, uint16_t symbolOffset = 0) {
        if (psyq->twoPartsReloc) {
            psyq->setElfConversionError("Two-part relocation missing its second part");
            return false;
        }
        if (expr) {
            auto symbol = psyq->symbols.find(expr->symbolIndex);
            if (symbol == psyq->symbols.end()) {
                psyq->setElfConversionError("Couldn't find symbol {} for relocation.", expr->symbolIndex);
                return false;
            }
            elfSym = symbol->elfSym;
        }
        auto elfType = typeMap.find(type);
        rela.add_entry(offset, elfSym, (unsigned char)elfType->second);
        ELFIO::Elf_Xword size = section->section->get_size();
        uint8_t* sectionData = (uint8_t*)malloc(size);
        memcpy(sectionData, section->section->get_data(), size);
        switch (type) {
            case PsyqRelocType::REL32: {
                sectionData[offset + 0] = 0;
                sectionData[offset + 1] = 0;
                sectionData[offset + 2] = 0;
                sectionData[offset + 3] = 0;
                break;
            }
            case PsyqRelocType::REL26: {
                sectionData[offset + 0] = symbolOffset >> 2;
                sectionData[offset + 1] = 0;
                sectionData[offset + 2] = 0;
                sectionData[offset + 3] &= 0xfc;
                break;
            }
            case PsyqRelocType::HI16:
            case PsyqRelocType::LO16:
            case PsyqRelocType::GPREL16: {
                sectionData[offset + 0] = 0;
                sectionData[offset + 1] = 0;
                break;
            }
            default:
                psyq->setElfConversionError("Unsupported relocation type {}.", magic_enum::enum_integer(type));
                return false;
        }
        section->section->set_data((char*)sectionData, size);
        free(sectionData);
        return true;
    };
    auto localSymbolReloc = [&](uint16_t sectionIndex, int32_t symbolOffset) {
        if (pass == ElfRelocationPass::PASS2) {
            skipped.skipped = true;
            return true;
        }
        auto section = psyq->sections.find(sectionIndex);
        if (section == psyq->sections.end()) {
            psyq->setElfConversionError("Section {} not found in relocation", sectionIndex);
            return false;
        }
        std::string symbolName = fmt::format("${}.rel{}@{:08x}", prefix, section->name, symbolOffset);
        auto existing = psyq->localElfSymbols.find(symbolName);
        ELFIO::Elf_Word elfSym;
        if (existing == psyq->localElfSymbols.end()) {
            fmt::print("      :: Creating local symbol {}\n", symbolName);
            elfSym = syma.add_symbol(stra, symbolName.c_str(), symbolOffset, 0, STB_LOCAL, STT_SECTION, 0,
                                     section->section->get_index());
            psyq->localElfSymbols.insert(std::make_pair(symbolName, elfSym));
        } else {
            elfSym = existing->second;
        }
        return simpleSymbolReloc(nullptr, elfSym, symbolOffset);
    };
    auto checkZero = [&](Expression* expr) {
        switch (expr->type) {
            case PsyqExprOpcode::SECTION_BASE: {
                return localSymbolReloc(expr->sectionIndex, 0);
            }
            case PsyqExprOpcode::SYMBOL: {
                if (pass == ElfRelocationPass::PASS1) {
                    skipped.skipped = true;
                    return true;
                }
                return simpleSymbolReloc(expr);
            }
            default: {
                psyq->setElfConversionError("Unsupported relocation expression type: {}",
                                            magic_enum::enum_integer(expr->type));
                return false;
            }
        }
    };
    auto check = [&, this](Expression* expr, int32_t addend) {
        switch (expr->type) {
            case PsyqExprOpcode::SECTION_BASE: {
                return localSymbolReloc(expr->sectionIndex, addend);
            }
            case PsyqExprOpcode::SYMBOL: {
                auto symbol = psyq->symbols.find(expr->symbolIndex);
                if (symbol == psyq->symbols.end()) {
                    psyq->setElfConversionError("Couldn't find symbol {} for relocation.", expr->symbolIndex);
                    return false;
                }
                if (symbol->symbolType != PsyqLnkFile::Symbol::Type::IMPORTED) {
                    return localSymbolReloc(symbol->sectionIndex, symbol->getOffset(psyq) + addend);
                }
                if (pass == ElfRelocationPass::PASS1) {
                    skipped.skipped = true;
                    return true;
                }
                ELFIO::Elf_Word elfSym = symbol->elfSym;
                // this is the most complex case, as the psyq format can do
                // relocations that have addend from a symbol, but ELF can't,
                // which means we need to alter the code's byte stream to
                // compute the proper addend.
                switch (type) {
                    case PsyqRelocType::HI16: {
                        if (psyq->twoPartsReloc) {
                            psyq->setElfConversionError("Two hi16 relocations in a row for a symbol with addend");
                            return false;
                        }
                        psyq->twoPartsRelocSymbol = expr->symbolIndex;
                        psyq->twoPartsRelocAddend = addend;
                        struct QueueTwoParts {
                            QueueTwoParts(PsyqLnkFile* psyq, Relocation* object) : psyq(psyq), object(object) {}
                            ~QueueTwoParts() { psyq->twoPartsReloc = object; }
                            PsyqLnkFile* psyq;
                            Relocation* object;
                        };
                        fmt::print("      :: Delaying relocation, waiting for LO16\n");
                        QueueTwoParts queue(psyq, this);
                        return simpleSymbolReloc(nullptr, elfSym);
                    }
                    case PsyqRelocType::LO16: {
                        auto hi = psyq->twoPartsReloc;
                        psyq->twoPartsReloc = nullptr;
                        if (!hi) {
                            psyq->setElfConversionError("Got lo16 for a symbol with added without a prior hi16");
                            return false;
                        }
                        if ((addend != psyq->twoPartsRelocAddend) || (expr->symbolIndex != psyq->twoPartsRelocSymbol)) {
                            psyq->setElfConversionError("Mismatching hi/lo symbol+addend relocation");
                            return false;
                        }
                        bool success = simpleSymbolReloc(nullptr, elfSym);
                        if (!success) return false;
                        ELFIO::Elf_Xword size = section->section->get_size();
                        uint8_t* sectionData = (uint8_t*)malloc(size);
                        memcpy(sectionData, section->section->get_data(), size);
                        fmt::print("      :: Altering bytestream to account for HI/LO symbol+addend relocation\n");
                        sectionData[offset + 0] = addend & 0xff;
                        addend >>= 8;
                        sectionData[offset + 1] = addend & 0xff;
                        addend >>= 8;
                        sectionData[hi->offset + 0] = addend & 0xff;
                        addend >>= 8;
                        sectionData[hi->offset + 1] = addend & 0xff;
                        addend >>= 8;
                        section->section->set_data((char*)sectionData, size);
                        free(sectionData);
                        return true;
                    }
                    default: {
                        psyq->setElfConversionError("Unsupported relocation from a symbol with an addend");
                        return false;
                    }
                }
            }
            default: {
                psyq->setElfConversionError("Unsupported relocation expression type: {}",
                                            magic_enum::enum_integer(expr->type));
                return false;
            }
        }
    };
    switch (expression->type) {
        case PsyqExprOpcode::ADD: {
            if (expression->right->type == PsyqExprOpcode::VALUE) {
                if ((expression->left->type == PsyqExprOpcode::SYMBOL) && (expression->right->value == 0)) {
                    return checkZero(expression->left.get());
                } else {
                    return check(expression->left.get(), expression->right->value);
                }
            } else if (expression->left->type == PsyqExprOpcode::VALUE) {
                if ((expression->right->type == PsyqExprOpcode::SYMBOL) && (expression->left->value == 0)) {
                    return checkZero(expression->right.get());
                } else {
                    return check(expression->right.get(), expression->left->value);
                }
            } else {
                psyq->setElfConversionError("Unsupported ADD operation in relocation");
                return false;
            }
            break;
        }
        case PsyqExprOpcode::SUB: {
            if (expression->right->type == PsyqExprOpcode::VALUE) {
                return check(expression->left.get(), -((int32_t)expression->right->value));
            } else {
                psyq->setElfConversionError("Unsupported SUB operation in relocation");
                return false;
            }
            break;
        }
        case PsyqExprOpcode::DIV: {
            psyq->setElfConversionError("Unsupported DIV operation in relocation");
            return false;
        }
        default: {
            return checkZero(expression.get());
        }
    }
}

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    auto output = args.get<std::string>("o");

    auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool noInput = inputs.size() == 0;
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    if (asksForHelp || noInput || (hasOutput && !oneInput)) {
        fmt::print(R"(
Usage: {} input.obj [input2.obj...] [-h] [-v] [-d] [-n] [-p prefix] [-o output.o]
  input.obj      mandatory: specify the input psyq LNK object file.
  -h             displays this help information and exit.
  -v             turns on verbose mode for the parser.
  -d             displays the parsed input file.
  -n             use "none" ABI instead of Linux.
  -p prefix      use this prefix for local symbols.
  -o output.o    tries to dump the parsed psyq LNK file into an ELF file;
                 can only work with a single input file.
)",
                   argv[0]);
        return -1;
    }

    bool verbose = args.get<bool>("v").value_or(false);

    int ret = 0;

    for (auto& input : inputs) {
        PCSX::IO<PCSX::File> file(new PCSX::PosixFile(input));
        if (file->failed()) {
            fmt::print(stderr, "Unable to open file: {}\n", input);
            ret = -2;
        } else {
            auto psyq = PsyqLnkFile::parse(file, verbose);
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
                    bool success = psyq->writeElf(prefix, output.value(), args.get<bool>("n").value_or(false));
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
