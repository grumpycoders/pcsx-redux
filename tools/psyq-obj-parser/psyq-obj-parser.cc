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
#include <ctype.h>
#include <stdio.h>

#include "support/file.h"
#include "support/slice.h"

enum class PsyqOpcode : uint8_t {
    END = 0,
    BYTES = 2,
    SWITCH = 6,
    ZEROES = 8,
    RELOCATION = 10,
    EXPORTED_SYMBOL = 12,
    EXTERNAL_SYMBOL = 14,
    SECTION = 16,
    LOCAL_SYMBOL = 18,
    FILE = 28,
    PROGRAMTYPE = 46,
    BSS = 48,
};

enum class PsyqReloc : uint8_t {
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

static std::string readPsyqString(PCSX::File* file) { return file->readString(file->byte()); }

static bool readExpression(PCSX::File* file, int level = 0) {
    bool ret = true;
    uint8_t exprOp = file->read<uint8_t>();
    printf("    ");
    for (int i = 0; i < level; i++) printf("  ");
    switch (exprOp) {
    case (uint8_t)PsyqExprOpcode::VALUE: {
        uint32_t value = file->read<uint32_t>();
        printf("Value: %08x\n", value);
        break;
    }
    case (uint8_t)PsyqExprOpcode::IMPORT: {
        uint16_t import = file->read<uint16_t>();
        printf("Import: %i\n", import);
        break;
    }
    case (uint8_t)PsyqExprOpcode::SECTION_BASE: {
        uint16_t sectionIndex = file->read<uint16_t>();
        printf("Base of section %i\n", sectionIndex);
        break;
    }
    case (uint8_t)PsyqExprOpcode::SECTION_START: {
        uint16_t sectionIndex = file->read<uint16_t>();
        printf("Start of section %i\n", sectionIndex);
        break;
    }
    case (uint8_t)PsyqExprOpcode::SECTION_END: {
        uint16_t sectionIndex = file->read<uint16_t>();
        printf("End of section %i\n", sectionIndex);
        break;
    }
    case (uint8_t)PsyqExprOpcode::ADD: {
        printf("Add:\n");
        ret = ret && readExpression(file, level + 1);
        ret = ret && readExpression(file, level + 1);
        break;
    }
    case (uint8_t)PsyqExprOpcode::SUB: {
        printf("Sub:\n");
        ret = ret && readExpression(file, level + 1);
        ret = ret && readExpression(file, level + 1);
        break;
    }
    case (uint8_t)PsyqExprOpcode::DIV: {
        printf("Div:\n");
        ret = ret && readExpression(file, level + 1);
        ret = ret && readExpression(file, level + 1);
        break;
    }
    default: {
        printf("Unknown! %i\n", exprOp);
        return false;
    }
    }
    return ret;
}

static int parsePsyq(PCSX::File* file) {
    printf(":: Reading signature.\n");
    std::string signature = file->readString(3);
    if (signature != "LNK") {
        printf(" --> Wrong signature.\n");
        return -1;
    }
    printf(" --> Signature ok.\n");

    printf(":: Reading version: ");
    uint8_t version = file->byte();
    printf("%02x\n", version);
    if (version != 2) {
        printf(" --> Unknown version.\n");
        return -1;
    }

    printf(":: Parsing file...\n");
    while (!file->eof()) {
        uint8_t opcode = file->byte();
        printf("  :: Read opcode %02x --> ", opcode);
        switch (opcode) {
        case (uint8_t)PsyqOpcode::END: {
            printf("EOF\n");
            return 0;
        }
        case (uint8_t)PsyqOpcode::BYTES: {
            uint16_t size = file->read<uint16_t>();
            printf("Bytes (%04x)\n", size);
            PCSX::Slice slice = file->read(size);
            std::string hex = slice.toHexString();
            printf("%s\n", hex.c_str());
            break;
        }
        case (uint8_t)PsyqOpcode::SWITCH: {
            uint16_t sectionIndex = file->read<uint16_t>();
            printf("Switch to section %i\n", sectionIndex);
            break;
        }
        case (uint8_t)PsyqOpcode::ZEROES: {
            uint32_t size = file->read<uint32_t>();
            printf("Zeroes (%04x)\n", size);
            break;
        }
        case (uint8_t)PsyqOpcode::RELOCATION: {
            uint8_t relocType = file->read<uint8_t>();
            printf("Relocation %i ", relocType);
            switch (relocType) {
            case (uint8_t)PsyqReloc::REL32: {
                printf("(REL32), ");
                break;
            }
            case (uint8_t)PsyqReloc::REL26: {
                printf("(REL26), ");
                break;
            }
            case (uint8_t)PsyqReloc::HI16: {
                printf("(HI16), ");
                break;
            }
            case (uint8_t)PsyqReloc::LO16: {
                printf("(LO16), ");
                break;
            }
            default: {
                printf("Unknown!\n");
                return -1;
            }
            }
            uint16_t offset = file->read<uint16_t>();
            printf("offset %04x, expression: \n", offset);
            bool okay = readExpression(file);
            if (!okay) {
                return -1;
            }
            break;
        }
        case (uint8_t)PsyqOpcode::EXPORTED_SYMBOL: {
            uint16_t symbolIndex = file->read<uint16_t>();
            uint16_t sectionIndex = file->read<uint16_t>();
            uint32_t offset = file->read<uint32_t>();
            std::string name = readPsyqString(file);
            printf("Export: id %i, section %i, offset %08x, name %s\n", symbolIndex, sectionIndex, offset,
                name.c_str());
            break;
        }
        case (uint8_t)PsyqOpcode::EXTERNAL_SYMBOL: {
            uint16_t symbolIndex = file->read<uint16_t>();
            std::string name = readPsyqString(file);
            printf("Import: symbol %i, name %s\n", symbolIndex, name.c_str());
            break;
        }
        case (uint8_t)PsyqOpcode::SECTION: {
            uint16_t symbolIndex = file->read<uint16_t>();
            uint16_t group = file->read<uint16_t>();
            uint8_t alignment = file->read<uint8_t>();
            std::string name = readPsyqString(file);
            printf("Section: symbol %i, group %i, alignment %i, name %s\n", symbolIndex, group, alignment,
                name.c_str());
            break;
        }
        case (uint8_t)PsyqOpcode::LOCAL_SYMBOL: {
            uint16_t symbolIndex = file->read<uint16_t>();
            uint32_t offset = file->read<uint32_t>();
            std::string name = readPsyqString(file);
            printf("Local: symbol %i, offset %08x, name %s\n", symbolIndex, offset, name.c_str());
            break;
        }
        case (uint8_t)PsyqOpcode::FILE: {
            uint16_t symbolIndex = file->read<uint16_t>();
            std::string name = readPsyqString(file);
            printf("File: symbol %i, name %s\n", symbolIndex, name.c_str());
            break;
        }
        case (uint8_t)PsyqOpcode::PROGRAMTYPE: {
            uint8_t type = file->read<uint8_t>();
            printf("Program type %i\n", type);
            if (type != 7) {
                return -1;
            }
            break;
        }
        case (uint8_t)PsyqOpcode::BSS: {
            uint16_t symbolIndex = file->read<uint16_t>();
            uint16_t sectionIndex = file->read<uint16_t>();
            uint32_t size = file->read<uint32_t>();
            std::string name = readPsyqString(file);
            printf("BSS section: symbol %i, section %i, size %08x, name %s\n", symbolIndex, sectionIndex, size,
                name.c_str());
            break;
        }
        default: {
            printf("Unknown %i!\n", opcode);
            return -1;
        }
        }
    }

    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <psyq object file>\n", argv[0]);
        return -1;
    }
    PCSX::File* file = new PCSX::File(argv[1]);
    if (file->failed()) {
        printf("Unable to open file: %s\n", argv[1]);
        delete file;
        return -1;
    }

    int ret = parsePsyq(file);
    assert(ret == 0);
    return ret;
}
