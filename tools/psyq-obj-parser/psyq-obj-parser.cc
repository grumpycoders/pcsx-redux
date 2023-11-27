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
    BLOCK_START = 78,
    BLOCK_END = 80,
    SECTION_DEF = 82,
    SECTION_DEF2 = 84,
    FUNCTION_START2 = 86,
};

enum class PsyqRelocType : uint8_t {
    REL32_BE = 8,
    REL32 = 16,
    REL26 = 74,
    HI16 = 82,
    LO16 = 84,
    REL26_BE = 92,
    HI16_BE = 96,
    LO16_BE = 98,
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
        int32_t addend;
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
    std::map<std::string, uint32_t> functionSizes;
    std::string elfConversionError;

    void display();
    bool writeElf(const std::string& prefix, const std::string& out, bool abiNone, bool bigEndian);
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
    uint32_t curFunctionStart = 0;
    std::string curFunctionName = "";

    vprint(":: Parsing file...\n");
    while (!file->eof()) {
        uint8_t opcode = file->byte();
        vprint("  :: Read opcode {} --> ", opcode);
        switch (opcode) {
            case (uint8_t)PsyqOpcode::END: {
                vprint("EOF\n");
                // Determine bss symbol placement
                // This has to be done after parsing the whole psyq object, as bss may be out of order in the file.
                // Doing it here ensures that we process symbols in their id order, instead of by psyq object file
                // order.
                for (auto& symbol : ret->symbols) {
                    // Static bss symbols will be represented as a ZEROES opcode instead of UNINITIALIZED.
                    // This will cause them to have a size of zero, so ignore size zero symbols here.
                    // Their relocs will resolve to an offset of the local .bss instead, so this causes no issues.
                    if (symbol.size > 0) {
                        auto section = ret->sections.find(symbol.sectionIndex);
                        if (section != ret->sections.end() && section->isBss()) {
                            auto align = std::min((uint32_t)section->alignment, symbol.size) - 1;
                            section->uninitializedOffset += align;
                            section->uninitializedOffset &= ~align;
                            symbol.offset = section->uninitializedOffset;
                            section->uninitializedOffset += symbol.size;
                        }
                    }
                }
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
                    case (uint8_t)PsyqRelocType::HI16_BE: {
                        vprint("(HI16 BE), ");
                        break;
                    }
                    case (uint8_t)PsyqRelocType::LO16_BE: {
                        vprint("(LO16 BE), ");
                        break;
                    }
                    case (uint8_t)PsyqRelocType::REL26_BE: {
                        vprint("(REL26 BE), ");
                        break;
                    }
                    case (uint8_t)PsyqRelocType::REL32_BE: {
                        vprint("(REL32 BE), ");
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
                // Addend will be populated later during expression evaluation
                section->relocations.emplace_back(
                    Relocation{PsyqRelocType(relocType), offset + section->pointer, 0, std::move(expression)});
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
                if (type != 7 && type != 9) {
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
                symbol->offset = 0;  // Filled in later
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
                curFunctionStart = offset;
                vprint(
                    "FUNCTION: section {}, offset {}, _file {}, startLine {}, frameReg {}, frameSize {}, retnPcReg {}, "
                    "mask {}, maskOffset {}, name {}\n",
                    section, offset, _file, startLine, frameReg, frameSize, retnPcReg, mask, maskOffset, name);
                curFunctionName = std::move(name);
                break;
            }
            case (uint8_t)PsyqOpcode::FUNCTION_END: {
                uint16_t section = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                uint32_t endLine = file->read<uint32_t>();
                ret->functionSizes[curFunctionName] = offset - curFunctionStart;
                vprint("FUNCTION_END: section {}, offset {}, endLine {}\n", section, offset, endLine);
                break;
            }
            case (uint8_t)PsyqOpcode::BLOCK_START: {
                uint16_t section = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                uint32_t start = file->read<uint32_t>();
                vprint("Block start at line {} in section {} with offset {:X}\n", start, section, offset);
                break;
            }
            case (uint8_t)PsyqOpcode::BLOCK_END: {
                uint16_t section = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                uint32_t end = file->read<uint32_t>();
                vprint("Block end at line {} in section {} with offset {:X}\n", end, section, offset);
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
            case (uint8_t)PsyqOpcode::FUNCTION_START2: {
                uint16_t section = file->read<uint16_t>();
                uint32_t offset = file->read<uint32_t>();
                uint16_t _file = file->read<uint16_t>();
                uint32_t startLine = file->read<uint32_t>();
                uint16_t frameReg = file->read<uint16_t>();
                uint32_t frameSize = file->read<uint32_t>();
                uint16_t retnPcReg = file->read<uint16_t>();
                uint32_t mask = file->read<uint32_t>();
                uint32_t maskOffset = file->read<uint32_t>();
                uint32_t unk1 = file->read<uint32_t>();
                uint32_t unk2 = file->read<uint32_t>();
                std::string name = readPsyqString(file);
                curFunctionStart = offset;
                vprint(
                    "FUNCTION: section {}, offset {}, _file {}, startLine {}, frameReg {}, frameSize {}, retnPcReg {}, "
                    "mask {}, maskOffset {}, name {}\n",
                    section, offset, _file, startLine, frameReg, frameSize, retnPcReg, mask, maskOffset, name);
                curFunctionName = std::move(name);
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
        {PsyqRelocType::REL32, "REL32"},       {PsyqRelocType::REL26, "REL26"},
        {PsyqRelocType::HI16, "HI16"},         {PsyqRelocType::LO16, "LO16"},
        {PsyqRelocType::GPREL16, "GPREL16"},   {PsyqRelocType::REL32_BE, "REL32 BE"},
        {PsyqRelocType::REL26_BE, "REL26 BE"}, {PsyqRelocType::HI16_BE, "HI16 BE"},
        {PsyqRelocType::LO16_BE, "LO16 BE"},
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
bool PsyqLnkFile::writeElf(const std::string& prefix, const std::string& out, bool abiNone, bool bigEndian) {
    ELFIO::elfio writer;
    writer.create(ELFIO::ELFCLASS32, bigEndian ? ELFIO::ELFDATA2MSB : ELFIO::ELFDATA2LSB);
    writer.set_os_abi(abiNone ? ELFIO::ELFOSABI_NONE : ELFIO::ELFOSABI_LINUX);
    writer.set_type(ELFIO::ET_REL);
    writer.set_machine(ELFIO::EM_MIPS);

    // conflate bigEndian with PSX vs N64
    if (bigEndian) {
        writer.set_flags(0x20001101);
    } else {
        writer.set_flags(0x1000);  // ?!
    }

    fmt::print("  :: Generating sections\n");
    for (auto& section : sections) {
        bool success = section.generateElfSection(this, writer);
        if (!success) return false;
    }

    ELFIO::section* str_sec = writer.sections.add(".strtab");
    str_sec->set_type(ELFIO::SHT_STRTAB);
    ELFIO::string_section_accessor stra(str_sec);
    ELFIO::section* sym_sec = writer.sections.add(".symtab");
    sym_sec->set_type(ELFIO::SHT_SYMTAB);
    sym_sec->set_addr_align(0x4);
    sym_sec->set_entry_size(writer.get_default_entry_size(ELFIO::SHT_SYMTAB));
    sym_sec->set_link(str_sec->get_index());
    ELFIO::symbol_section_accessor syma(writer, sym_sec);

    syma.add_symbol(stra, out.c_str(), 0, ELFIO::STB_LOCAL, ELFIO::STT_FILE, 0, ELFIO::SHN_ABS);

    fmt::print("  :: Generating relocations - pass 1, local only\n");
    for (auto& section : sections) {
        bool success = section.generateElfRelocations(ElfRelocationPass::PASS1, prefix, this, writer,
                                                      sym_sec->get_index(), stra, syma);
        if (!success) return false;
    }

    fmt::print("  :: Generating symbols\n");
    // Generate local symbols first
    for (auto& symbol : symbols) {
        if (symbol.symbolType == Symbol::Type::LOCAL) {
            bool success = symbol.generateElfSymbol(this, stra, syma);
            if (!success) return false;
        }
    }

    sym_sec->set_info(syma.get_symbols_num());

    // Generate all other symbols afterwards
    for (auto& symbol : symbols) {
        if (symbol.symbolType != Symbol::Type::LOCAL) {
            bool success = symbol.generateElfSymbol(this, stra, syma);
            if (!success) return false;
        }
    }

    fmt::print("  :: Generating relocations - pass 2, globals only\n");
    for (auto& section : sections) {
        bool success = section.generateElfRelocations(ElfRelocationPass::PASS2, prefix, this, writer,
                                                      sym_sec->get_index(), stra, syma);
        if (!success) return false;
    }

    ELFIO::section* note = writer.sections.add(".note");
    note->set_type(ELFIO::SHT_NOTE);

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

    fmt::print("    :: Generating symbol {} {} {}\n", name, getOffset(psyq), sectionIndex);
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
    uint32_t functionSize = 0;
    if (isText) {
        auto functionSizeIter = psyq->functionSizes.find(name);
        if (functionSizeIter != psyq->functionSizes.end()) {
            functionSize = functionSizeIter->second;
        }
    }
    elfSym = syma.add_symbol(stra, name.c_str(), getOffset(psyq), isText ? functionSize : size,
                             symbolType == Type::LOCAL ? ELFIO::STB_LOCAL : ELFIO::STB_GLOBAL,
                             isText ? ELFIO::STT_FUNC : ELFIO::STT_NOTYPE, 0, elfSectionIndex);
    return true;
}

bool PsyqLnkFile::Section::generateElfSection(PsyqLnkFile* psyq, ELFIO::elfio& writer) {
    if (getFullSize() == 0) return true;
    fmt::print("    :: Generating section {}\n", name);
    static const std::map<std::string, ELFIO::Elf_Xword> flagsMap = {
        {".text", ELFIO::SHF_ALLOC | ELFIO::SHF_EXECINSTR},
        {".rdata", ELFIO::SHF_ALLOC},
        {".data", ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE},
        {".sdata", ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE | SHF_MIPS_GPREL},
        {".bss", ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE},
        {".sbss", ELFIO::SHF_ALLOC | ELFIO::SHF_WRITE | SHF_MIPS_GPREL},
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
    section->set_type(isBss() ? ELFIO::SHT_NOBITS : ELFIO::SHT_PROGBITS);
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

static const std::map<PsyqRelocType, elf_mips_reloc_type> typeMap = {
    {PsyqRelocType::REL32, elf_mips_reloc_type::R_MIPS_32},
    {PsyqRelocType::REL26, elf_mips_reloc_type::R_MIPS_26},
    {PsyqRelocType::HI16, elf_mips_reloc_type::R_MIPS_HI16},
    {PsyqRelocType::LO16, elf_mips_reloc_type::R_MIPS_LO16},
    {PsyqRelocType::GPREL16, elf_mips_reloc_type::R_MIPS_GPREL16},
    {PsyqRelocType::REL26_BE, elf_mips_reloc_type::R_MIPS_26},
    {PsyqRelocType::HI16_BE, elf_mips_reloc_type::R_MIPS_HI16},
    {PsyqRelocType::LO16_BE, elf_mips_reloc_type::R_MIPS_LO16},
    {PsyqRelocType::REL32_BE, elf_mips_reloc_type::R_MIPS_32},
};

bool PsyqLnkFile::Section::generateElfRelocations(ElfRelocationPass pass, const std::string& prefix, PsyqLnkFile* psyq,
                                                  ELFIO::elfio& writer, ELFIO::Elf_Word symbolSectionIndex,
                                                  ELFIO::string_section_accessor& stra,
                                                  ELFIO::symbol_section_accessor& syma) {
    if (relocations.size() == 0) return true;
    if (pass == ElfRelocationPass::PASS1) {
        rel_sec = writer.sections.add(fmt::format(".rel{}", name));
        rel_sec->set_type(ELFIO::SHT_REL);
        rel_sec->set_info(section->get_index());
        rel_sec->set_addr_align(0x4);
        rel_sec->set_entry_size(writer.get_default_entry_size(ELFIO::SHT_REL));
        rel_sec->set_link(symbolSectionIndex);
    }
    ELFIO::relocation_section_accessor rela(writer, rel_sec);

    for (auto& relocation : relocations) {
        bool success = relocation.generateElf(pass, prefix, psyq, this, writer, stra, syma, rela);
        if (!success) return false;
    }

    // Pair any stray HI16 relocs with a previous matching one so that relocation addends are handled correctly
    if (pass == ElfRelocationPass::PASS2) {
        ELFIO::Elf_Xword num_relocs = rela.get_entries_num();
        // Create a dummy type to represent a reloc, which is 8 bytes
        using reloc_t = std::array<char, 8>;
        // Get the pointer to the reloc table's data
        const reloc_t* reloc_table = (const reloc_t*)rel_sec->get_data();
        // Allocate a buffer to hold a copy of the reloc table when modifying it
        std::vector<reloc_t> reloc_table_copy(num_relocs);
        // Vector to hold the true addend of each reloc table entry
        std::vector<int32_t> reloc_addends(num_relocs);
        // Copy the reloc table into the working buffer
        std::copy_n(reloc_table, num_relocs, reloc_table_copy.begin());

        // Lambda that finds a reloc from relocations given a type and offset, writing a reference to it to `out`
        // Returns the index of the reloc in relocations if a reloc was found, -1 if not
        auto find_reloc = [&](elf_mips_reloc_type type, uint32_t offset, int32_t& out) {
            int idx = 0;
            for (auto& cur_reloc : relocations) {
                elf_mips_reloc_type corresponding_reloc_type = typeMap.at(cur_reloc.type);
                if (cur_reloc.offset == offset && corresponding_reloc_type == (elf_mips_reloc_type)type) {
                    out = cur_reloc.addend;
                    return idx;
                }
                ++idx;
            }
            return -1;
        };

        // Do an initial pass to get the full addend for each reloc
        for (ELFIO::Elf_Xword reloc_idx = 0; reloc_idx < num_relocs; ++reloc_idx) {
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol;
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword fake_addend;  // Addend isn't encoded in the reloc, so this value is useless
            rela.get_entry(reloc_idx, offset, symbol, type, fake_addend);

            // We need to correlate Relocation objects to elf reloc table entries in order to get full addends, since
            // they're not in the same order
            int found_idx = find_reloc((elf_mips_reloc_type)type, (uint32_t)offset, reloc_addends[reloc_idx]);
        }

        // Check every entry to see if it's a stray HI16
        for (ELFIO::Elf_Xword reloc_idx = 0; reloc_idx < num_relocs; ++reloc_idx) {
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol;
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword fake_addend;              // Addend isn't encoded in the reloc, so this value is useless
            int32_t addend = reloc_addends[reloc_idx];  // This will instead contain the full 32 bit addend
            rela.get_entry(reloc_idx, offset, symbol, type, fake_addend);

            // Check if this is a HI16
            if ((elf_mips_reloc_type)type == elf_mips_reloc_type::R_MIPS_HI16) {
                bool stray_reloc;
                if (reloc_idx + 1 >= num_relocs) {
                    // Make sure that we don't overrun the reloc table
                    stray_reloc = true;
                } else {
                    ELFIO::Elf_Xword checked_idx = reloc_idx + 1;
                    ELFIO::Elf64_Addr checked_offset;
                    ELFIO::Elf_Word checked_symbol;
                    ELFIO::Elf_Word checked_type;
                    ELFIO::Elf_Sxword checked_fake_addend;
                    int32_t checked_addend;
                    // Loop through relocs until we hit one that isn't identical to the current one or until we hit the
                    // end of the symbol table
                    do {
                        rela.get_entry(checked_idx, checked_offset, checked_symbol, checked_type, checked_fake_addend);
                        checked_addend = reloc_addends[checked_idx];
                        ++checked_idx;
                    } while (checked_idx + 1 < num_relocs &&
                             (elf_mips_reloc_type)checked_type == elf_mips_reloc_type::R_MIPS_HI16 &&
                             symbol == checked_symbol && addend == checked_addend);

                    // Check if we ended up at a LO16 with the same symbol and full addend as the HI16
                    // If so, then this HI16 (and any that we passed over) is paired correctly
                    if ((elf_mips_reloc_type)checked_type == elf_mips_reloc_type::R_MIPS_LO16 &&
                        symbol == checked_symbol && addend == checked_addend) {
                        stray_reloc = false;
                        // We can skip straight to the next reloc, as we've also verified all of the ones up the LO16 we
                        // found
                        reloc_idx = checked_idx + 1;
                    } else {
                        stray_reloc = true;
                    }
                }
                if (stray_reloc) {
                    // Find the matching LO16
                    ELFIO::Elf_Xword checked_idx;
                    ELFIO::Elf64_Addr checked_offset;
                    ELFIO::Elf_Word checked_symbol;
                    ELFIO::Elf_Word checked_type;
                    ELFIO::Elf_Sxword checked_fake_addend;
                    int32_t checked_addend;

                    ELFIO::Elf_Xword matching_idx = -1;

                    // Loop through relocs until we find a LO16 with a matching offset, symbol, and addend
                    for (checked_idx = 0; checked_idx < num_relocs; ++checked_idx) {
                        rela.get_entry(checked_idx, checked_offset, checked_symbol, checked_type, checked_fake_addend);
                        checked_addend = reloc_addends[checked_idx];
                        // Check if this is a LO16 that matches
                        if (checked_symbol == symbol && checked_addend == addend &&
                            (elf_mips_reloc_type)checked_type == elf_mips_reloc_type::R_MIPS_LO16) {
                            matching_idx = checked_idx;
                            break;
                        }
                    }

                    if (matching_idx != -1) {
                        if (matching_idx < reloc_idx) {
                            // Move the HI16 backwards so it's before the LO16
                            // This is effectively rotating the subset of the reloc table to the right
                            //   so that the HI16 ends up at the start of the rotated output
                            std::rotate(std::make_reverse_iterator(reloc_table_copy.begin() + reloc_idx + 1),
                                        std::make_reverse_iterator(reloc_table_copy.begin() + reloc_idx),
                                        std::make_reverse_iterator(reloc_table_copy.begin() + matching_idx));
                            std::rotate(std::make_reverse_iterator(reloc_addends.begin() + reloc_idx + 1),
                                        std::make_reverse_iterator(reloc_addends.begin() + reloc_idx),
                                        std::make_reverse_iterator(reloc_addends.begin() + matching_idx));
                        } else {
                            // Shift the HI16 forwards so it's before the LO16
                            // This is effectively rotating the subset of the reloc table to the left
                            //   so that the HI16 ends up at the start of the rotated output
                            std::rotate(reloc_table_copy.begin() + reloc_idx, reloc_table_copy.begin() + reloc_idx + 1,
                                        reloc_table_copy.begin() + matching_idx);
                            std::rotate(reloc_addends.begin() + reloc_idx, reloc_addends.begin() + reloc_idx + 1,
                                        reloc_addends.begin() + matching_idx);
                        }

                        // Update the reloc table so that get_entry is valid for the next iteration
                        rel_sec->set_data((char*)reloc_table_copy.data(), num_relocs * sizeof(reloc_t));
                    }
                }
            }
        }
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
    auto simpleSymbolReloc = [&, this](Expression* expr, ELFIO::Elf_Word elfSym = 0, int32_t symbolOffset = 0) {
        if (expr) {
            auto symbol = psyq->symbols.find(expr->symbolIndex);
            if (symbol == psyq->symbols.end()) {
                psyq->setElfConversionError("Couldn't find symbol {} for relocation.", expr->symbolIndex);
                return false;
            }
            elfSym = symbol->elfSym;
        }
        if (type == PsyqRelocType::HI16_BE || type == PsyqRelocType::LO16_BE) {
            offset -= 0x2;
        }
        auto elfType = typeMap.find(type);
        // TODO get_entries_num to get the new entry index and insert the symbolOffset into a vector for referencing
        // later to be used for reloc pairing
        rela.add_entry(offset, elfSym, (unsigned char)elfType->second);
        ELFIO::Elf_Xword size = section->section->get_size();
        uint8_t* sectionData = (uint8_t*)malloc(size);
        memcpy(sectionData, section->section->get_data(), size);
        switch (type) {
            case PsyqRelocType::REL32: {
                sectionData[offset + 0] = (uint8_t)(symbolOffset >> 0x00);
                sectionData[offset + 1] = (uint8_t)(symbolOffset >> 0x08);
                sectionData[offset + 2] = (uint8_t)(symbolOffset >> 0x10);
                sectionData[offset + 3] = (uint8_t)(symbolOffset >> 0x18);
                break;
            }
            case PsyqRelocType::REL26: {
                sectionData[offset + 0] = (uint8_t)(symbolOffset >> 0x02);
                sectionData[offset + 1] = (uint8_t)(symbolOffset >> 0x0A);
                sectionData[offset + 2] = (uint8_t)(symbolOffset >> 0x12);
                sectionData[offset + 3] &= 0xfc;
                sectionData[offset + 3] |= (uint8_t)(symbolOffset >> 0x1A);
                break;
            }
            case PsyqRelocType::HI16: {
                // Calculate the high reloc, accounting for the signedness of the corresponding low reloc
                uint16_t hi = symbolOffset >> 16;
                if (symbolOffset & 0x8000) {
                    hi += 1;
                }
                sectionData[offset + 0] = (uint8_t)(hi >> 8);
                sectionData[offset + 1] = (uint8_t)(hi >> 0);
                break;
            }
            case PsyqRelocType::LO16: {
                // Calculate the low reloc
                uint16_t lo = symbolOffset & 0xFFFF;
                sectionData[offset + 0] = (uint8_t)(lo >> 0);
                sectionData[offset + 1] = (uint8_t)(lo >> 8);
                break;
            }
            case PsyqRelocType::GPREL16: {
                sectionData[offset + 0] = 0;
                sectionData[offset + 1] = 0;
                break;
            }
            case PsyqRelocType::REL32_BE: {
                sectionData[offset + 3] = (uint8_t)(symbolOffset >> 0x00);
                sectionData[offset + 2] = (uint8_t)(symbolOffset >> 0x08);
                sectionData[offset + 1] = (uint8_t)(symbolOffset >> 0x10);
                sectionData[offset + 0] = (uint8_t)(symbolOffset >> 0x18);
                break;
            }
            case PsyqRelocType::REL26_BE: {
                sectionData[offset + 3] = (uint8_t)(symbolOffset >> 0x02);
                sectionData[offset + 2] = (uint8_t)(symbolOffset >> 0x0A);
                sectionData[offset + 1] = (uint8_t)(symbolOffset >> 0x12);
                sectionData[offset + 0] &= 0xfc;
                sectionData[offset + 0] |= (uint8_t)(symbolOffset >> 0x1A);
                break;
            }
            case PsyqRelocType::HI16_BE: {
                // Calculate the high reloc, accounting for the signedness of the corresponding low reloc
                uint16_t hi = symbolOffset >> 16;
                if (symbolOffset & 0x8000) {
                    hi += 1;
                }
                sectionData[offset + 3] = (uint8_t)(hi >> 0);
                sectionData[offset + 2] = (uint8_t)(hi >> 8);
                break;
            }
            case PsyqRelocType::LO16_BE: {
                // Calculate the low reloc
                uint16_t lo = symbolOffset & 0xFFFF;
                sectionData[offset + 3] = (uint8_t)(lo >> 0);
                sectionData[offset + 2] = (uint8_t)(lo >> 8);
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
    auto localSymbolReloc = [&, this](uint16_t sectionIndex, int32_t symbolOffset) {
        if (pass == ElfRelocationPass::PASS2) {
            skipped.skipped = true;
            return true;
        }
        auto section = psyq->sections.find(sectionIndex);
        if (section == psyq->sections.end()) {
            psyq->setElfConversionError("Section {} not found in relocation", sectionIndex);
            return false;
        }
        bool useLocalSymOffsets = true;
        std::string symbolName =
            useLocalSymOffsets ? section->name : fmt::format("${}.rel{}@{:08x}", prefix, section->name, symbolOffset);
        auto existing = psyq->localElfSymbols.find(symbolName);
        ELFIO::Elf_Word elfSym;
        if (existing == psyq->localElfSymbols.end()) {
            elfSym = syma.add_symbol(stra, symbolName.c_str(), useLocalSymOffsets ? 0 : symbolOffset, 0,
                                     ELFIO::STB_LOCAL, ELFIO::STT_SECTION, 0, section->section->get_index());
            psyq->localElfSymbols.insert(std::make_pair(symbolName, elfSym));
        } else {
            elfSym = existing->second;
        }
        return simpleSymbolReloc(nullptr, elfSym, symbolOffset);
    };
    auto checkZero = [&, this](Expression* expr) {
        this->addend = 0;
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
        this->addend = addend;
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
                        bool success = simpleSymbolReloc(nullptr, elfSym);
                        if (!success) return false;
                        ELFIO::Elf_Xword size = section->section->get_size();
                        uint8_t* sectionData = (uint8_t*)malloc(size);
                        memcpy(sectionData, section->section->get_data(), size);
                        fmt::print("      :: Altering bytestream to account for HI symbol+addend relocation\n");
                        addend >>= 16;
                        sectionData[offset + 0] = addend & 0xff;
                        addend >>= 8;
                        sectionData[offset + 1] = addend & 0xff;
                        addend >>= 8;
                        section->section->set_data((char*)sectionData, size);
                        free(sectionData);
                        return true;
                    }
                    case PsyqRelocType::LO16: {
                        bool success = simpleSymbolReloc(nullptr, elfSym);
                        if (!success) return false;
                        ELFIO::Elf_Xword size = section->section->get_size();
                        uint8_t* sectionData = (uint8_t*)malloc(size);
                        memcpy(sectionData, section->section->get_data(), size);
                        fmt::print("      :: Altering bytestream to account for LO symbol+addend relocation\n");
                        sectionData[offset + 0] = addend & 0xff;
                        addend >>= 8;
                        sectionData[offset + 1] = addend & 0xff;
                        addend >>= 8;
                        section->section->set_data((char*)sectionData, size);
                        free(sectionData);
                        return true;
                    }
                    // Handled already
                    case PsyqRelocType::REL32_BE:
                    case PsyqRelocType::HI16_BE:
                    case PsyqRelocType::LO16_BE: {
                        bool success = simpleSymbolReloc(nullptr, elfSym, addend);
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
                // Why
                if (expression->left->type == PsyqExprOpcode::ADD) {
                    if (expression->left->left->type == PsyqExprOpcode::VALUE) {
                        return check(expression->left->right.get(),
                                     expression->left->left->value - expression->right->value);
                    }
                } else {
                    return check(expression->left.get(), -((int32_t)expression->right->value));
                }
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
  -b             output a big-endian ELF file.
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
                    bool success = psyq->writeElf(prefix, output.value(), args.get<bool>("n").value_or(false),
                                                  args.get<bool>("b").value_or(false));
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
