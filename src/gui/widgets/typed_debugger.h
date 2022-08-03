
/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <string>
#include <unordered_map>
#include <vector>

#include "imgui.h"

struct GhidraData {
    std::string type;
    std::string name;
    size_t size;
};

struct GhidraFunction {
    std::string name;
    std::vector<GhidraData> arguments;
};

struct ReadWriteLogEntry {
    enum class AccessType { Read = 0x1, Write = 0x2 };

    uint32_t instructionAddress;
    std::string functionName;
    AccessType accessType;
};

// A WatchTreeNode contains the information necessary for displaying a type hierarchy in a tree.
struct WatchTreeNode {
    std::string type;
    std::string name;
    size_t size;
    std::vector<WatchTreeNode> children;
    std::vector<ReadWriteLogEntry> logEntries;
};

// For an explanation of the meaning of addressOfPointer, see declaration of displayNode().
struct AddressNodeTuple {
    uint32_t address;
    bool addressOfPointer;
    WatchTreeNode node;
};

namespace PCSX {
class GUI;
namespace Widgets {

class TypedDebugger {
  public:
    void draw(const char* title, GUI* gui);
    bool& m_show;
    TypedDebugger(bool& show);

    enum class ImportType { DataTypes, Functions };
    void import(const char* filename, const ImportType& importType);

    // Functions.
    // Redundancy so we can have both in-order traversal and fast O(1) lookup.
    std::vector<uint32_t> m_addresses;
    std::unordered_map<uint32_t, GhidraFunction> m_functions;
    std::unordered_map<uint32_t, std::array<uint8_t, 8>> m_toggledFunctions;
    std::unordered_map<uint32_t, std::array<uint8_t, 4>> m_toggledInstructions;

    // Structures.
    using structFields = std::vector<GhidraData>;
    std::unordered_map<std::string, structFields> m_structs;

    std::vector<AddressNodeTuple> m_displayedWatchData;

    struct FunctionBreakpointData {
        std::string functionName;
        std::vector<AddressNodeTuple> argData;
    };
    std::vector<FunctionBreakpointData> m_displayedFunctionData;

    // The last parameter, addressOfPointer, is used for pointer nodes:
    // - if it is true, then currentAddress is the address of the pointer that *stores* the pointee address;
    // - if not, then currentAddress *is* the pointee address.
    void displayNode(WatchTreeNode* node, const uint32_t currentAddress, const uint32_t memBase, uint8_t* memData,
                     uint32_t memSize, bool watchView, bool addressOfPointer);
};

}  // namespace Widgets

}  // namespace PCSX
