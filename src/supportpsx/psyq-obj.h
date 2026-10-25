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

#pragma once

#include <assert.h>
#include <stdint.h>

#include <list>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "elfio/elfio.hpp"
#include "fmt/format.h"
#include "support/file.h"
#include "support/list.h"
#include "support/slice.h"
#include "support/tree.h"
#include "support/windowswrapper.h"

namespace PCSX {

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
    INC_SLD_LINENUM_BY_WORD = 54,
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
    GPREL16_BE = 12,
    REL32 = 16,
    GPREL16_LE = 30,
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
    static std::unique_ptr<PsyqLnkFile> parse(PCSX::IO<PCSX::File> file, bool verbose, bool sorted,
                                              bool convertCommToBss);
    static std::string readPsyqString(PCSX::IO<PCSX::File> file) { return file->readString(file->byte()); }

    /* Our list of sections and symbols will be keyed by their id from the LNK file */
    typedef PCSX::Intrusive::Tree<uint16_t, Section> SectionTree;
    typedef PCSX::Intrusive::List<Section> SectionList;
    typedef PCSX::Intrusive::Tree<uint16_t, Symbol> SymbolTree;
    typedef PCSX::Intrusive::List<Symbol> SymbolList;

    struct Section : public SectionTree::Node, public SectionList::Node {
        uint16_t group;
        uint8_t alignment;
        std::string name;
        uint32_t zeroes = 0;
        uint32_t uninitializedOffset = 0;
        PCSX::Slice data;
        std::list<Relocation> relocations;
        uint32_t getFullSize() { return data.size() + zeroes + uninitializedOffset; }
        uint32_t pointer = 0;
        uint16_t getKey() { return getLow(); }

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
    struct Symbol : public SymbolTree::Node, public SymbolList::Node {
        enum class Type {
            LOCAL,
            EXPORTED,
            IMPORTED,
            UNINITIALIZED,
            COMM,
        } symbolType;
        uint16_t sectionIndex;
        uint32_t offset = 0;
        uint32_t size = 0;
        std::string name;
        ELFIO::Elf_Word elfSym;
        uint16_t getKey() { return getLow(); }
        uint32_t getCommAlignment() const {
            if (size >= 8) {
                return 8;
            } else if (size >= 4) {
                return 4;
            } else if (size >= 2) {
                return 2;
            } else {
                return 1;
            }
        }
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

    SectionTree sections;
    SectionList sectionsList;
    SectionList unseenSectionsList;
    SymbolTree symbols;
    SymbolList symbolsList;
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

    ~PsyqLnkFile() {
        sectionsList.destroyAll();
        symbolsList.destroyAll();
    }
};

}  // namespace PCSX
