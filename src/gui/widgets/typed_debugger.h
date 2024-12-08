
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
#include <variant>
#include <vector>

#include "core/debug.h"
#include "gui/widgets/filedialog.h"
#include "imgui.h"
#include "support/eventbus.h"

namespace PCSX {
class GUI;
namespace Widgets {

class TypedDebugger {
  public:
    void draw(const char* title, GUI* gui);
    bool& m_show;
    TypedDebugger(bool& show, std::vector<std::string>& favorites);

  private:
    /**
     * Data importation.
     */
    std::vector<PCSX::u8string> m_dataTypesFile;
    Widgets::FileDialog<> m_importDataTypesFileDialog;
    std::vector<PCSX::u8string> m_functionsFile;
    Widgets::FileDialog<> m_importFunctionsFileDialog;
    enum class ImportType { DataTypes, Functions };
    void import(std::string_view filename, ImportType importType);

    /**
     * Class structs.
     */

    // Represents the type-name-size tuple for either a struct field or a function argument.
    struct FieldOrArgumentData {
        std::string type;
        std::string name;
        size_t size;
    };

    // Information about a read/write instruction, including the name of the function from which it was emitted.
    struct ReadWriteLogEntry {
        enum class AccessType { Read, Write };

        uint32_t instructionAddress;
        std::string functionName;
        AccessType accessType;
    };

    // A WatchTreeNode contains the information necessary for displaying a type hierarchy in a tree.
    struct WatchTreeNode {
        std::string type;
        std::string name;
        size_t size = 0;
        std::vector<WatchTreeNode> children;
        std::vector<ReadWriteLogEntry> logEntries;
    };

    using StructFields = std::vector<FieldOrArgumentData>;
    // Populates a node according to its type.
    void populate(WatchTreeNode* node);

    // For an explanation of the meaning of addressOfPointer, see declaration of displayNode().
    struct AddressNodeTuple {
        uint32_t address;
        bool addressOfPointer;
        WatchTreeNode node;
    };

    struct DebuggerFunction {
        std::string name;
        std::vector<FieldOrArgumentData> arguments;
    };

    // Represents an immediate value, as opposed to one stored at an address in memory.
    struct ImmediateValue {
        uint32_t value;
        std::string type;
        std::string name;
        size_t size = 0;
    };

    /**
     * Data types.
     */

    std::unordered_map<std::string, StructFields> m_structs;
    std::vector<std::string> m_typeNames;

    /**
     * Watch.
     */

    std::vector<AddressNodeTuple> m_displayedWatchData;
    std::vector<PCSX::Debug::Breakpoint*> m_watchBreakpoints;
    std::unordered_map<uint32_t, std::array<uint8_t, 4>> m_disabledInstructions;
    bool m_hex = false;
    uint32_t m_newValue = 0;

    /**
     * Functions.
     */

    std::vector<uint32_t> m_functionAddresses;
    std::unordered_map<uint32_t, DebuggerFunction> m_functions;

    struct FunctionBreakpointData {
        uint32_t id;
        std::string functionName;
        std::string callerName;
        uint32_t callerAddress;
        using ArgumentData = std::variant<AddressNodeTuple, ImmediateValue>;
        std::vector<ArgumentData> argData;
    };
    std::vector<FunctionBreakpointData> m_displayedFunctionData;
    std::vector<PCSX::Debug::Breakpoint*> m_functionBreakpoints;
    std::unordered_map<uint32_t, std::array<uint8_t, 8>> m_disabledFunctions;

    // Returns the name of the function from which the instruction at the given address was emitted if found, an empty
    // string otherwise.
    std::string_view getFunctionNameFromInstructionAddress(uint32_t address);
    std::unordered_map<uint32_t, std::string> m_instructionAddressToFunctionMap;

    /**
     * Display.
     */

    // The last parameter, addressOfPointer, is used for pointer nodes:
    // - if it is true, then currentAddress is the address of the pointer that *stores* the pointee address;
    // - if not, then currentAddress *is* the pointee address.
    void displayNode(WatchTreeNode* node, const uint32_t currentAddress, bool watchView, bool addressOfPointer,
                     uint32_t extraImGuiId = 0);
    void printValue(const char* type, size_t type_size, void* address);
    void displayNewValueInput(const char* type, size_t size_type, void* address);
    void displayBreakpointOptions(WatchTreeNode* node, const uint32_t address);

    /**
     * Event handling.
     */

    EventBus::Listener m_listener;
};

}  // namespace Widgets

}  // namespace PCSX
