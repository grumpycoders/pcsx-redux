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
#include <map>

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
    SYMBOL = 2,
    SECTION_BASE = 4,
    SECTION_START = 12,
    SECTION_END = 22,
    ADD = 44,
    SUB = 46,
    DIV = 50,
};

struct PsyqLnkFile;

struct PsyqExpression {
    PsyqExprOpcode type;
    std::unique_ptr<PsyqExpression> left = nullptr;
    std::unique_ptr<PsyqExpression> right = nullptr;
    uint32_t value;
    uint16_t symbolIndex;
    uint16_t sectionIndex;
    void display(PsyqLnkFile* lnk, bool top = false);
};

struct PsyqRelocation;

struct PsyqLnkFile {
    struct Section;
    struct Symbol;
    typedef PCSX::Intrusive::HashTable<uint16_t, Section> SectionHashTable;
    typedef PCSX::Intrusive::HashTable<uint16_t, Symbol> SymbolHashTable;
    std::string elfConversionError;
    struct Section : public SectionHashTable::Node {
        uint16_t group;
        uint8_t alignment;
        std::string name;
        uint32_t zeroes = 0;
        uint32_t uninitializedOffset = 0;
        PCSX::Slice data;
        std::list<PsyqRelocation> relocations;
        uint32_t getFullSize() { return data.size() + zeroes + uninitializedOffset; }
        ELFIO::section* section = nullptr;
        void display(PsyqLnkFile* lnk) {
            fmt::print("    {:04x}   {:04x}   {:8}   {:08x}   {:08x}   {:08x}   {:08x}   {}\n", getKey(), group,
                       alignment, getFullSize(), data.size(), zeroes, uninitializedOffset, name);
        }
        void displayRelocs(PsyqLnkFile* lnk);
        bool isBss() { return (name == ".bss") || (name == ".sbss"); }
        bool generateElfSection(PsyqLnkFile* psyq, ELFIO::elfio& writer) {
            if (getFullSize() == 0) return true;
            static const std::map<std::string, ELFIO::Elf_Xword> flagsMap = {
                {".text", SHF_ALLOC | SHF_EXECINSTR}, {".rdata", SHF_ALLOC},
                {".data", SHF_ALLOC | SHF_WRITE},     {".bss", SHF_ALLOC | SHF_WRITE},
                {".sbss", SHF_ALLOC | SHF_WRITE},
            };
            auto flags = flagsMap.find(name);
            if (flags == flagsMap.end()) {
                psyq->elfConversionError = fmt::format("Unknown section type '{}'", name);
                return false;
            }
            if (isBss() && data.size()) {
                psyq->elfConversionError = fmt::format("Section {} looks like bss, but has data", name);
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
        bool generateElfRelocations(PsyqLnkFile* psyq, ELFIO::elfio& writer, ELFIO::Elf_Word symbolSectionIndex,
                                    ELFIO::string_section_accessor& stra, ELFIO::symbol_section_accessor& syma);
    };
    struct Symbol : public SymbolHashTable::Node {
        enum class Type {
            EXPORTED,
            IMPORTED,
            UNINITIALIZED,
        } symbolType;
        uint16_t sectionIndex;
        uint32_t offset = 0;
        uint32_t size = 0;
        std::string name;
        ELFIO::Elf_Word elfSym;
        void display(PsyqLnkFile* lnk) {
            if (symbolType == Type::EXPORTED) {
                auto section = lnk->sections.find(sectionIndex);
                if (section == lnk->sections.end()) {
                    fmt::print("** BROKEN SYMBOL AT INDEX {:04x} **\n", getKey());
                } else {
                    fmt::print("    {:04x}   {:6}   ({:04x})  {:12}   {:08x}   {:8}   {}\n", getKey(), "EXPORT",
                               sectionIndex, section->name, offset, "", name);
                }
            } else if (symbolType == Type::IMPORTED) {
                fmt::print("    {:04x}   {:6}   {:6}  {:12}   {:8}   {:8}   {}\n", getKey(), "IMPORT", "", "", "", "",
                           name);
            } else {
                auto section = lnk->sections.find(sectionIndex);
                if (section == lnk->sections.end()) {
                    fmt::print("** BROKEN SYMBOL AT INDEX {:04x} **\n", getKey());
                } else {
                    fmt::print("    {:04x}   {:6}   ({:04x})  {:12}   {:8}   {:08x}   {}\n", getKey(), "UNDEFN",
                               sectionIndex, section->name, "", size, name);
                }
            }
        }
        bool generateElfSymbol(PsyqLnkFile* psyq, ELFIO::string_section_accessor& stra,
                               ELFIO::symbol_section_accessor& syma) {
            ELFIO::Elf_Half elfSectionIndex = 0;
            if (symbolType != Type::IMPORTED) {
                auto section = psyq->sections.find(sectionIndex);
                if (section == psyq->sections.end()) {
                    psyq->elfConversionError = fmt::format("Couldn't find section index {} for symbol {} ('{}')",
                                                           sectionIndex, getKey(), name);
                    return false;
                }
                elfSectionIndex = section->section->get_index();
            }
            elfSym = syma.add_symbol(stra, name.c_str(), offset, size, STB_GLOBAL, STT_NOTYPE, 0, elfSectionIndex);
            return true;
        }
    };
    Section* getCurrentSection() {
        auto section = sections.find(currentSection);
        if (section == sections.end()) return nullptr;
        return &*section;
    }
    uint16_t currentSection = 0xffff;
    bool gotProgramSeven = false;
    SectionHashTable sections;
    SymbolHashTable symbols;
    void display() {
        fmt::print("  :: Symbols\n\n");
        fmt::print("    {:^4}   {:^6}   {:^6}  {:^12}   {:^8}   {:^8}   {}\n", "indx", "type", "sectn", "", "offset",
                   "size", "name");
        fmt::print("    -----------------------------------------------------------------\n");
        for (auto& symbol : symbols) {
            symbol.display(this);
        }
        fmt::print("\n\n\n  :: Sections\n\n");
        fmt::print("    {:4}   {:4}   {:8}   {:8}   {:8}   {:8}   {:8}   {}\n", "indx", "grp", "alignmnt", "size",
                   "data", "zeroes", "alloc", "name");
        fmt::print("    -------------------------------------------------------------------------\n");
        for (auto& section : sections) {
            section.display(this);
        }
        fmt::print("\n\n\n  :: Relocations\n\n");
        fmt::print("    {:5}   {:>12}::{:8}  {}\n", "type", "section", "offset", "expression");
        fmt::print("    ------------------------------------------\n");
        for (auto& section : sections) {
            section.displayRelocs(this);
        }
    }
    bool writeElf(const std::string& out, bool abiNone) {
        ELFIO::elfio writer;
        writer.create(ELFCLASS32, ELFDATA2LSB);
        writer.set_os_abi(abiNone ? ELFOSABI_NONE : ELFOSABI_LINUX);
        writer.set_type(ET_REL);
        writer.set_machine(EM_MIPS);

        for (auto& section : sections) {
            bool success = section.generateElfSection(this, writer);
            if (!success) return false;
        }

        ELFIO::section* str_sec = writer.sections.add(".strtab");
        str_sec->set_type(SHT_STRTAB);
        ELFIO::string_section_accessor stra(str_sec);
        ELFIO::section* sym_sec = writer.sections.add(".symtab");
        sym_sec->set_type(SHT_SYMTAB);
        sym_sec->set_info(2);
        sym_sec->set_addr_align(0x4);
        sym_sec->set_entry_size(writer.get_default_entry_size(SHT_SYMTAB));
        sym_sec->set_link(str_sec->get_index());
        ELFIO::symbol_section_accessor syma(writer, sym_sec);

        for (auto& symbol : symbols) {
            bool success = symbol.generateElfSymbol(this, stra, syma);
            if (!success) return false;
        }

        for (auto& section : sections) {
            bool success = section.generateElfRelocations(this, writer, sym_sec->get_index(), stra, syma);
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
};

enum elf_mips_reloc_type {
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
    elf_mips_reloc_type_size
};

struct PsyqRelocation {
    PsyqRelocType type;
    uint32_t offset;
    std::unique_ptr<PsyqExpression> expression;
    bool generateElf(PsyqLnkFile* psyq, PsyqLnkFile::Section* section, ELFIO::elfio& writer,
                     ELFIO::string_section_accessor& stra, ELFIO::symbol_section_accessor& syma,
                     ELFIO::relocation_section_accessor& rela) {
        static const std::map<PsyqRelocType, unsigned char> typeMap = {
            {PsyqRelocType::REL32, R_MIPS_32},
            {PsyqRelocType::REL26, R_MIPS_26},
            {PsyqRelocType::HI16, R_MIPS_HI16},
            {PsyqRelocType::LO16, R_MIPS_LO16},
        };
        auto simpleSymbolReloc = [&, this](PsyqExpression* expr) {
            auto symbol = psyq->symbols.find(expr->symbolIndex);
            if (symbol == psyq->symbols.end()) {
                psyq->elfConversionError = fmt::format("Couldn't find symbol {} for relocation.", expr->symbolIndex);
                return false;
            }
            auto elfType = typeMap.find(type);
            rela.add_entry(offset, symbol->elfSym, elfType->second);
            return true;
        };
        switch (expression->type) {
            case PsyqExprOpcode::SYMBOL: {
                return simpleSymbolReloc(expression.get());
            }
            case PsyqExprOpcode::ADD: {
                auto checkZero = [&, this](PsyqExpression* expr) {
                    switch (expr->type) {
                        case PsyqExprOpcode::SYMBOL: {
                            return simpleSymbolReloc(expr);
                        }
                        default: {
                            psyq->elfConversionError =
                                fmt::format("Unsupported relocation expression type: {}", expr->type);
                            return false;
                        }
                    }
                };
                auto check = [&, this](PsyqExpression* expr, uint32_t addend) {
                    switch (expr->type) {
                        default: {
                            psyq->elfConversionError =
                                fmt::format("Unsupported relocation expression type: {}", expr->type);
                            return false;
                        }
                    }
                };
                if (expression->right->type == PsyqExprOpcode::VALUE) {
                    if (expression->right->value == 0) {
                        return checkZero(expression->left.get());
                    } else {
                        return check(expression->left.get(), expression->right->value);
                    }
                } else if (expression->left->type == PsyqExprOpcode::VALUE) {
                    if (expression->left->value == 0) {
                        return checkZero(expression->right.get());
                    } else {
                        return check(expression->right.get(), expression->left->value);
                    }
                } else {
                    psyq->elfConversionError = fmt::format("Unsupported ADD operation in relocation");
                    return false;
                }
                break;
            }
            default: {
                psyq->elfConversionError = fmt::format("Unsupported relocation expression type: {}", expression->type);
                return false;
            }
        }
    }
    void display(PsyqLnkFile* lnk, PsyqLnkFile::Section* sec) {
        static const std::map<PsyqRelocType, std::string> typeStr = {
            {PsyqRelocType::REL32, "REL32"},
            {PsyqRelocType::REL26, "REL26"},
            {PsyqRelocType::HI16, "HI16"},
            {PsyqRelocType::LO16, "LO16"},
        };
        fmt::print("    {:5}   {:>12}::{:08x}  ", typeStr.find(type)->second, sec->name, offset);
        expression->display(lnk, true);
    }
};

void PsyqExpression::display(PsyqLnkFile* lnk, bool top) {
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

void PsyqLnkFile::Section::displayRelocs(PsyqLnkFile* lnk) {
    for (auto& reloc : relocations) {
        reloc.display(lnk, this);
        fmt::print("\n");
    }
}

bool PsyqLnkFile::Section::generateElfRelocations(PsyqLnkFile* psyq, ELFIO::elfio& writer,
                                                  ELFIO::Elf_Word symbolSectionIndex,
                                                  ELFIO::string_section_accessor& stra,
                                                  ELFIO::symbol_section_accessor& syma) {
    if (relocations.size() == 0) return true;
    ELFIO::section* rel_sec = writer.sections.add(fmt::format(".rel{}", name));
    rel_sec->set_type(SHT_REL);
    rel_sec->set_info(section->get_index());
    rel_sec->set_addr_align(0x4);
    rel_sec->set_entry_size(writer.get_default_entry_size(SHT_REL));
    rel_sec->set_link(symbolSectionIndex);
    ELFIO::relocation_section_accessor rela(writer, rel_sec);

    for (auto& relocation : relocations) {
        bool success = relocation.generateElf(psyq, this, writer, stra, syma, rela);
        if (!success) return false;
    }
    return true;
}

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

static std::unique_ptr<PsyqLnkFile> parsePsyq(PCSX::File* file) {
    std::unique_ptr<PsyqLnkFile> ret = std::make_unique<PsyqLnkFile>();
    vprint(":: Reading signature.\n");
    std::string signature = file->readString(3);
    if (signature != "LNK") {
        fmt::print("Wrong signature: {}\n", signature);
        return nullptr;
    }
    vprint(" --> Signature ok.\n");

    vprint(":: Reading version: ");
    uint8_t version = file->byte();
    vprint("{}\n", version);
    if (version != 2) {
        fmt::print("Unknown version {}\n", version);
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
                    default: {
                        fmt::print("Unknown relocation type {}\n", relocType);
                        return nullptr;
                    }
                }
                uint16_t offset = file->read<uint16_t>();
                vprint("offset {:04x}, expression: \n", offset);
                std::unique_ptr<PsyqExpression> expression = readExpression(file);
                if (!expression) return nullptr;
                auto section = ret->getCurrentSection();
                if (!section) {
                    fmt::print("Section {} not found\n", ret->currentSection);
                    return nullptr;
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
                symbol->symbolType = PsyqLnkFile::Symbol::Type::EXPORTED;
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
                PsyqLnkFile::Symbol* symbol = new PsyqLnkFile::Symbol();
                symbol->symbolType = PsyqLnkFile::Symbol::Type::IMPORTED;
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
                PsyqLnkFile::Section* section = new PsyqLnkFile::Section();
                section->group = group;
                section->alignment = alignment;
                section->name = name;
                ret->sections.insert(sectionIndex, section);
                break;
            }
            case (uint8_t)PsyqOpcode::PROGRAMTYPE: {
                uint8_t type = file->read<uint8_t>();
                vprint("Program type {}\n", type);
                if (type != 7) {
                    fmt::print("Unknown program type {}\n", type);
                    return nullptr;
                }
                if (ret->gotProgramSeven) {
                    fmt::print("Already got program type.\n");
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
                vprint("Uninitialized: id {}, section {}, size {:08x}, name {}\n", symbolIndex, sectionIndex, size,
                       name);
                PsyqLnkFile::Symbol* symbol = new PsyqLnkFile::Symbol();
                symbol->symbolType = PsyqLnkFile::Symbol::Type::UNINITIALIZED;
                symbol->sectionIndex = sectionIndex;
                symbol->size = size;
                symbol->name = name;
                auto section = ret->sections.find(sectionIndex);
                if (section == ret->sections.end()) {
                    fmt::print("Section {} not found.\n", sectionIndex);
                    return nullptr;
                }
                symbol->offset = section->uninitializedOffset;
                section->uninitializedOffset += size;
                ret->symbols.insert(symbolIndex, symbol);
                break;
            }
            default: {
                fmt::print("Unknown opcode {}.\n", opcode);
                return nullptr;
            }
        }
    }

    fmt::print("Got actual end of file before EOF command.\n");

    return nullptr;
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
Usage: {} input.obj [input2.obj...] [-h] [-v] [-d] [-n] [-o output.o]
  input.obj      mandatory: specify the input psyq LNK object file.
  -h             displays this help information and exit.
  -v             turns on verbose mode for the parser.
  -d             displays the parsed input file.
  -n             use "none" ABI instead of Linux.
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
            auto psyq = parsePsyq(file);
            if (!psyq) {
                ret = -1;
            } else {
                if (args.get<bool>("d").value_or(false)) {
                    fmt::print(":: Displaying {}\n", input);
                    psyq->display();
                    fmt::print("\n\n\n");
                }
                if (hasOutput) {
                    fmt::print("Converting {} to {}...", input, output.value());
                    bool success = psyq->writeElf(output.value(), args.get<bool>("n").value_or(false));
                    if (success) {
                        fmt::print(" done.\n");
                    } else {
                        fmt::print(" conversion failed: {}\n", psyq->elfConversionError);
                    }
                }
            }
        }
        delete file;
    }

    return ret;
}
