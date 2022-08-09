
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

#include "gui/widgets/typed_debugger.h"

#include <fstream>
#include <magic_enum/include/magic_enum.hpp>
#include <regex>
#include <sstream>

#include "core/psxemulator.h"
#include "core/system.h"
#include "gui/gui.h"
#include "imgui.h"
#include "imgui_stdlib.h"

void PCSX::Widgets::TypedDebugger::import(std::string_view fileContents, ImportType importType) {
    std::istringstream file(std::string(fileContents), std::ios_base::in);
    std::string line;
    while (std::getline(file, line)) {
        // For data types.
        std::string name;
        std::vector<FieldOrArgumentData> fields;

        // For functions.
        uint32_t address;
        DebuggerFunction func;

        std::stringstream ss(line);
        std::string s;
        int linePartsCounter = 0;
        while (std::getline(ss, s, ';')) {
            if (linePartsCounter == 0) {
                switch (importType) {
                    case ImportType::DataTypes:
                        // @todo: implement robust typedef handling.
                        if (s.front() == '_') {
                            s.erase(0, 1);
                        }
                        name = s;
                        ++linePartsCounter;
                        continue;
                        break;
                    case ImportType::Functions:
                        address = std::stoul(s, nullptr, 16);
                        m_functionAddresses.push_back(address);
                        ++linePartsCounter;
                        continue;
                        break;
                    default:
                        break;
                }
            }
            if (importType == ImportType::Functions && linePartsCounter == 1) {
                func.name = s;
                ++linePartsCounter;
                continue;
            }

            FieldOrArgumentData data;
            const std::regex data_regex(R"(([\w\s\*\[\]]+),(\w+),(\d+))");
            std::smatch matches;
            if (std::regex_match(s, matches, data_regex)) {
                data.type = matches[1].str();
                data.name = matches[2].str();
                data.size = std::stoul(matches[3].str());
            }

            switch (importType) {
                case ImportType::DataTypes:
                    fields.push_back(data);
                    break;
                case ImportType::Functions:
                    func.arguments.push_back(data);

                    ++linePartsCounter;
                    // Address + name + 4 arguments = 6.
                    if (linePartsCounter == 6) {
                        break;
                    }
                    break;
                default:
                    break;
            }
        }
        switch (importType) {
            case ImportType::DataTypes:
                m_structs[name] = fields;
                m_typeNames.push_back(name);
                break;
            case ImportType::Functions:
                m_functions[address] = func;
                break;
            default:
                break;
        }
    }

    if (importType == ImportType::DataTypes) {
        std::sort(m_typeNames.begin(), m_typeNames.end(), [](std::string left, std::string right) {
            for (auto& letter : left) {
                letter = tolower(letter);
            }
            for (auto& letter : right) {
                letter = tolower(letter);
            }
            return left.compare(right) < 0;
        });
    }
}

PCSX::Widgets::TypedDebugger::TypedDebugger(bool& show) : m_show(show), m_listener(g_system->m_eventBus) {
    m_listener.listen<PCSX::Events::ExecutionFlow::Reset>([this](const auto& event) {
        m_displayedWatchData.clear();
        for (const auto* bp : m_watchBreakpoints) {
            g_emulator->m_debug->removeBreakpoint(bp);
        }
        m_watchBreakpoints.clear();
        m_disabledInstructions.clear();

        m_displayedFunctionData.clear();
        for (const auto* bp : m_functionBreakpoints) {
            g_emulator->m_debug->removeBreakpoint(bp);
        }
        m_functionBreakpoints.clear();
        m_disabledFunctions.clear();
    });
}

void PCSX::Widgets::TypedDebugger::populate(WatchTreeNode* node,
                                            std::unordered_map<std::string, StructFields>& structs_info) {
    const auto type = node->type;

    const std::regex arrayRegex(R"((.*)\[(\d+)\])");
    std::smatch matches;
    if (std::regex_match(type, matches, arrayRegex)) {
        const auto type = matches[1].str();
        const auto numChildren = std::stoul(matches[2].str());
        for (size_t i = 0; i < numChildren; ++i) {
            WatchTreeNode newNode{type, std::string(node->name + "[" + std::to_string(i) + "]"),
                                  node->size / numChildren};
            node->children.push_back(newNode);
            populate(&node->children.back(), structs_info);
        }
    } else if (structs_info.contains(type)) {
        const size_t numChildren = structs_info[type].size();

        for (size_t i = 0; i < numChildren; ++i) {
            const auto& field = structs_info[type][i];
            WatchTreeNode newNode{field.type, field.name, field.size};
            node->children.push_back(newNode);
            populate(&node->children.back(), structs_info);
        }
    }
}

static bool isInRAM(uint32_t address) {
    uint32_t memBase = 0x80000000;
    uint32_t memSize = 1024 * 1024 * (PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>() ? 8 : 2);
    return address >= memBase && address < memBase + memSize;
}

// Returns the appropriate pointer if the given address is in RAM or in the scratchpad, in which case the memory base
// address is stored in outMemBase; otherwise, a null pointer is returned and no value is assigned to MemBase.
static uint8_t* getMemoryPointerFor(uint32_t address, uint32_t& outMemBase) {
    if (isInRAM(address)) {
        outMemBase = 0x80000000;
        return PCSX::g_emulator->m_mem->m_psxM;
    }

    const uint32_t memBase = 0x1f800000;
    const uint32_t memSize = 1024;
    if (address >= memBase && address < memBase + memSize) {
        outMemBase = memBase;
        return PCSX::g_emulator->m_mem->m_psxH;
    }

    return nullptr;
}

static bool equals(const char* lhs, const char* rhs) { return strcmp(lhs, rhs) == 0; }

static bool isPrimitive(const char* type) {
    // Don't test against "char" since char* is handled specially.
    return equals(type, "uchar") || equals(type, "u_char") || equals(type, "short") || equals(type, "ushort") ||
           equals(type, "u_short") || equals(type, "int") || equals(type, "long") || equals(type, "uint") ||
           equals(type, "u_int") || equals(type, "ulong") || equals(type, "u_long");
}

void PCSX::Widgets::TypedDebugger::displayBreakpointOptions(WatchTreeNode* node, const uint32_t address,
                                                            uint8_t* memData, const uint32_t memBase) {
    const auto readBreakpointButtonName = fmt::format(f_("Add read breakpoint##{}{}"), node->name.c_str(), address);
    if (ImGui::Button(readBreakpointButtonName.c_str())) {
        auto* newBreakpoint = PCSX::g_emulator->m_debug->addBreakpoint(address, PCSX::Debug::BreakpointType::Read,
                                                                       node->size, _("Typed Debugger"));
        m_watchBreakpoints.push_back(newBreakpoint);
    }
    ImGui::SameLine();
    const auto writeBreakpointButtonName = fmt::format(f_("Add write breakpoint##{}{}"), node->name.c_str(), address);
    if (ImGui::Button(writeBreakpointButtonName.c_str())) {
        auto* newBreakpoint = PCSX::g_emulator->m_debug->addBreakpoint(address, PCSX::Debug::BreakpointType::Write,
                                                                       node->size, _("Typed Debugger"));
        m_watchBreakpoints.push_back(newBreakpoint);
    }
    ImGui::SameLine();
    const auto logReadsWritesButtonName = fmt::format(f_("Log reads and writes##{}{}"), node->name.c_str(), address);
    if (ImGui::Button(logReadsWritesButtonName.c_str())) {
        PCSX::Debug::BreakpointInvoker logReadsWritesInvoker =
            [this, node](const PCSX::Debug::Breakpoint* self, uint32_t address, unsigned width, const char* cause) {
                if (!node) {
                    return false;
                }

                const auto pc = g_emulator->m_cpu->m_regs.pc;
                std::string funcName = getFunctionNameFromInstructionAddress(pc);
                if (funcName.empty()) {
                    funcName = "overlay?";
                }
                ReadWriteLogEntry::AccessType accessType =
                    equals(cause, "Read") ? ReadWriteLogEntry::AccessType::Read : ReadWriteLogEntry::AccessType::Write;

                for (const auto& logEntry : node->logEntries) {
                    if (logEntry.instructionAddress == pc) {
                        return true;
                    }
                }

                ReadWriteLogEntry newLogEntry{pc, funcName, accessType};
                node->logEntries.push_back(newLogEntry);
                return true;
            };

        auto* newReadBreakpoint = PCSX::g_emulator->m_debug->addBreakpoint(
            address, PCSX::Debug::BreakpointType::Read, node->size, _("Read"), logReadsWritesInvoker);
        auto* newWriteBreakpoint = PCSX::g_emulator->m_debug->addBreakpoint(
            address, PCSX::Debug::BreakpointType::Write, node->size, _("Write"), logReadsWritesInvoker);
        m_watchBreakpoints.push_back(newReadBreakpoint);
        m_watchBreakpoints.push_back(newWriteBreakpoint);
    }

    if (node->logEntries.size() > 0) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();  // Name.
        bool open = ImGui::TreeNodeEx(fmt::format(f_("Display log entries##{}{}"), node->name.c_str(), address).c_str(),
                                      ImGuiTreeNodeFlags_SpanFullWidth);
        ImGui::TableNextColumn();  // Type.
        ImGui::TextDisabled("--");
        ImGui::TableNextColumn();  // Size.
        ImGui::TextDisabled("--");
        ImGui::TableNextColumn();  // Value.
        ImGui::TextDisabled("--");
        ImGui::TableNextColumn();  // Breakpoints.
        if (open) {
            uint32_t accumulatedOffset = 0;
            for (const auto& logEntry : node->logEntries) {
                const auto instructionAddress = logEntry.instructionAddress;

                ImGui::TableNextRow();
                ImGui::TableNextColumn();  // Name.
                ImGui::TextUnformatted(logEntry.functionName.c_str());
                ImGui::TableNextColumn();  // Type.
                ImGui::Text("0x%2x", instructionAddress);
                ImGui::TableNextColumn();  // Size.
                ImGui::TextUnformatted(magic_enum::enum_name(logEntry.accessType).data());
                ImGui::TableNextColumn();  // Value.
                const bool functionToggledOff = m_disabledInstructions.contains(instructionAddress);
                auto toggleButtonName = functionToggledOff ? fmt::format(f_("Re-enable##{}"), instructionAddress)
                                                           : fmt::format(f_("Disable##{}"), instructionAddress);
                if (ImGui::Button(toggleButtonName.c_str())) {
                    auto* instructionMem = memData + instructionAddress - memBase;
                    if (functionToggledOff) {
                        memcpy(instructionMem, m_disabledInstructions[instructionAddress].data(), 4);
                        m_disabledInstructions.erase(instructionAddress);
                    } else {
                        uint8_t instructions[4];
                        memcpy(instructions, instructionMem, 4);
                        m_disabledInstructions[instructionAddress] = std::to_array(instructions);
                        static constexpr uint8_t nop[4] = {0x00, 0x00, 0x00, 0x00};
                        memcpy(instructionMem, nop, 4);
                    }
                }
                ImGui::TableNextColumn();  // Access.
            }
            ImGui::TreePop();
        }
    }
}

std::string PCSX::Widgets::TypedDebugger::getFunctionNameFromInstructionAddress(uint32_t address) {
    if (m_instructionAddressToFunctionMap.contains(address)) {
        return m_instructionAddressToFunctionMap[address];
    } else {
        for (size_t i = 0; i < m_functionAddresses.size() - 1; ++i) {
            if (address >= m_functionAddresses[i] && address < m_functionAddresses[i + 1]) {
                const auto knownAddress = m_functionAddresses[i];
                m_instructionAddressToFunctionMap[address] = m_functions[knownAddress].name;
                return m_instructionAddressToFunctionMap[address];
            }
        }
    }
    return std::string();
}

void PCSX::Widgets::TypedDebugger::displayNode(WatchTreeNode* node, const uint32_t currentAddress, bool watchView,
                                               bool addressOfPointer, uint32_t extraImGuiId) {
    uint32_t memBase;
    uint8_t* memData = getMemoryPointerFor(currentAddress, memBase);

    ImGui::TableNextRow();
    ImGui::TableNextColumn();  // Name.
    std::string nameColumnString = fmt::format(f_("{}\t@ {:#x}##{}"), node->name, currentAddress, extraImGuiId);

    const char* nodeType = node->type.c_str();
    const bool isPointer = node->type.back() == '*';
    uint32_t startAddress = currentAddress;
    if (isPointer && addressOfPointer && memData) {
        const uint32_t offset = currentAddress - memBase;
        memcpy(&startAddress, memData + offset, 4);
    }
    memData = getMemoryPointerFor(startAddress, memBase);

    if (node->children.size() > 0) {  // If this is a struct, array or already populated pointer, display children.
        const bool isExpandable = (!isPointer || memData);  // Don't allow expanding a null pointer.
        const auto additionalTreeFlags =
            isExpandable ? ImGuiTreeNodeFlags_None
                         : (ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_Bullet | ImGuiTreeNodeFlags_NoTreePushOnOpen);

        // We need
        // 	&& isExpandable
        // because TreeNodeEx() always returns true for a non-expandable and therefore non-pushed tree, which would
        // lead us to try to pop a tree we haven't pushed.
        bool open =
            ImGui::TreeNodeEx(nameColumnString.c_str(), ImGuiTreeNodeFlags_SpanFullWidth | additionalTreeFlags) &&
            isExpandable;
        ImGui::TableNextColumn();  // Type.
        ImGui::TextUnformatted(node->type.c_str());
        ImGui::TableNextColumn();  // Size.
        ImGui::Text("%zu", node->size);
        ImGui::TableNextColumn();  // Value.
        if (isPointer) {
            ImGui::Text("0x%2x", startAddress);
        } else {
            ImGui::TextDisabled("--");
        }
        ImGui::TableNextColumn();  // Breakpoints.
        if (watchView) {
            displayBreakpointOptions(node, currentAddress, memData, memBase);
        } else if (isInRAM(currentAddress)) {
            auto addToWatchButtonName = fmt::format(f_("Add to Watch tab##{}{}"), currentAddress, extraImGuiId);
            if (ImGui::Button(addToWatchButtonName.c_str())) {
                m_displayedWatchData.push_back({currentAddress, addressOfPointer, *node});
            }
        }
        if (open) {
            uint32_t accumulatedOffset = 0;
            for (int child_n = 0; child_n < node->children.size(); child_n++) {
                displayNode(&node->children[child_n], startAddress + accumulatedOffset, watchView, true);
                accumulatedOffset += node->children[child_n].size;
            }
            ImGui::TreePop();
        }
    } else if (isPointer) {  // If this is an unpopulated pointer, populate it.
        ImGui::TreeNodeEx(nameColumnString.c_str(), ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_Bullet |
                                                        ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                                        ImGuiTreeNodeFlags_SpanFullWidth);
        ImGui::TableNextColumn();  // Type.
        ImGui::TextUnformatted(nodeType);
        // @todo: for pointers to non-char primitives, offer the option of displaying them as an array of a given number
        // of elements.
        if (isPrimitive(node->type.substr(0, node->type.find(' ')).c_str()) || equals(nodeType, "void *")) {
            ImGui::TableNextColumn();  // Size.
            ImGui::TextUnformatted("4");
            ImGui::TableNextColumn();  // Value.
            ImGui::Text("0x%2x", startAddress);
            ImGui::SameLine();
            const auto showMemButtonName = fmt::format(f_("Show in memory editor##{}{}"), currentAddress, extraImGuiId);
            if (ImGui::Button(showMemButtonName.c_str())) {
                const uint32_t editorAddress = startAddress - memBase;
                g_system->m_eventBus->signal(PCSX::Events::GUI::JumpToMemory{editorAddress, 4});
            }
            ImGui::TableNextColumn();  // Breakpoints.
            if (watchView) {
                displayBreakpointOptions(node, currentAddress, memData, memBase);
            }
            return;
        }
        if (equals(nodeType, "char *")) {
            const bool pointsToString = (memData != nullptr);
            auto* str = pointsToString ? (char*)memData + startAddress - memBase : nullptr;
            const auto strLength = pointsToString ? strlen(str) + 1 : 0;

            ImGui::TableNextColumn();  // Size.
            ImGui::Text("4 (string: %zu)", strLength);
            ImGui::TableNextColumn();  // Value.
            if (pointsToString) {
                ImGui::Text("%s", str);
                ImGui::SameLine();
                const auto showMemButtonName =
                    fmt::format(f_("Show in memory editor##{}{}"), currentAddress, extraImGuiId);
                if (ImGui::Button(showMemButtonName.c_str())) {
                    const uint32_t editorAddress = startAddress - memBase;
                    g_system->m_eventBus->signal(
                        PCSX::Events::GUI::JumpToMemory{editorAddress, static_cast<unsigned>(strLength)});
                }
            }
            ImGui::TableNextColumn();  // Breakpoints.
            if (watchView) {
                displayBreakpointOptions(node, currentAddress, memData, memBase);
            }
            return;
        }
        const auto pointerType = node->type;
        const auto pointedToType = node->type.substr(0, node->type.size() - 2);
        node->type = pointedToType;
        populate(node, m_structs);
        node->type = pointerType;
    } else {  // This is a primitive.
        ImGui::TreeNodeEx(nameColumnString.c_str(), ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_Bullet |
                                                        ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                                        ImGuiTreeNodeFlags_SpanFullWidth);
        ImGui::TableNextColumn();  // Type.
        ImGui::TextUnformatted(node->type.c_str());
        ImGui::TableNextColumn();  // Size.
        ImGui::Text("%zu", node->size);
        ImGui::TableNextColumn();  // Value.
        const auto basic_offset = startAddress - memBase;
        uint8_t* memValue = memData + basic_offset;
        const auto* nodeType = node->type.c_str();
        printValue(nodeType, memValue, true);
        ImGui::TableNextColumn();  // Breakpoints.
        if (watchView) {
            displayBreakpointOptions(node, currentAddress, memData, memBase);
        }
    }
}

void PCSX::Widgets::TypedDebugger::printValue(const char* type, void* address, bool editable) {
    static char s[64];
    static const int8_t step = 1;
    static const int8_t stepFast = 100;
    const auto signedFormat = m_hex ? "%x" : "%d";
    const auto unsignedFormat = m_hex ? "%x" : "%u";
    if (equals(type, "char")) {
        int8_t fieldValue = 0;
        memcpy(&fieldValue, address, 1);
        sprintf(s, "%d (0x%2x) \n", fieldValue, fieldValue);
        ImGui::Text("Value: %s", s);
        if (editable &&
            ImGui::InputScalar(fmt::format(f_("New value##{}"), address).c_str(), ImGuiDataType_S8, &m_newValue, &step,
                               &stepFast, signedFormat, ImGuiInputTextFlags_EnterReturnsTrue)) {
            memcpy(address, &m_newValue, 1);
            m_newValue = 0;
        }
    } else if (equals(type, "uchar") || equals(type, "u_char")) {
        uint8_t fieldValue = 0;
        memcpy(&fieldValue, address, 1);
        sprintf(s, "%u (0x%2x) \n", fieldValue, fieldValue);
        ImGui::Text("Value: %s", s);
        if (editable &&
            ImGui::InputScalar(fmt::format(f_("New value##{}"), address).c_str(), ImGuiDataType_U8, &m_newValue, &step,
                               &stepFast, unsignedFormat, ImGuiInputTextFlags_EnterReturnsTrue)) {
            memcpy(address, &m_newValue, 1);
            m_newValue = 0;
        }
    } else if (equals(type, "short")) {
        int16_t fieldValue = 0;
        memcpy(&fieldValue, address, 2);
        sprintf(s, "%hi (0x%2x) \n", fieldValue, fieldValue);
        ImGui::Text("Value: %s", s);
        if (editable &&
            ImGui::InputScalar(fmt::format(f_("New value##{}"), address).c_str(), ImGuiDataType_S16, &m_newValue, &step,
                               &stepFast, signedFormat, ImGuiInputTextFlags_EnterReturnsTrue)) {
            memcpy(address, &m_newValue, 2);
            m_newValue = 0;
        }
    } else if (equals(type, "ushort") || equals(type, "u_short")) {
        uint16_t fieldValue = 0;
        memcpy(&fieldValue, address, 2);
        sprintf(s, "%hu (0x%2x) \n", fieldValue, fieldValue);
        ImGui::Text("Value: %s", s);
        if (editable &&
            ImGui::InputScalar(fmt::format(f_("New value##{}"), address).c_str(), ImGuiDataType_U16, &m_newValue, &step,
                               &stepFast, unsignedFormat, ImGuiInputTextFlags_EnterReturnsTrue)) {
            memcpy(address, &m_newValue, 2);
            m_newValue = 0;
        }
    } else if (equals(type, "int") || equals(type, "long")) {
        int32_t fieldValue = 0;
        memcpy(&fieldValue, address, 4);
        sprintf(s, "%i (0x%2x) \n", fieldValue, fieldValue);
        ImGui::Text("Value: %s", s);
        if (editable &&
            ImGui::InputScalar(fmt::format(f_("New value##{}"), address).c_str(), ImGuiDataType_S32, &m_newValue, &step,
                               &stepFast, signedFormat, ImGuiInputTextFlags_EnterReturnsTrue)) {
            memcpy(address, &m_newValue, 4);
            m_newValue = 0;
        }
    } else if (equals(type, "uint") || equals(type, "u_int") || equals(type, "ulong") || equals(type, "u_long")) {
        uint32_t fieldValue = 0;
        memcpy(&fieldValue, address, 4);
        sprintf(s, "%u (0x%2x) \n", fieldValue, fieldValue);
        ImGui::Text("Value: %s", s);
        if (editable &&
            ImGui::InputScalar(fmt::format(f_("New value##{}"), address).c_str(), ImGuiDataType_U32, &m_newValue, &step,
                               &stepFast, unsignedFormat, ImGuiInputTextFlags_EnterReturnsTrue)) {
            memcpy(address, &m_newValue, 4);
            m_newValue = 0;
        }
    } else {
        sprintf(s, "\t> cannot yet print out value of type %s\n", type);
    }
}

void PCSX::Widgets::TypedDebugger::draw(const char* title, GUI* gui) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    bool showImportDataTypesFileDialog = false;
    if (m_structs.empty()) {
        ImGui::TextWrapped(
            "Data types can be imported from Ghidra using tools/ghidra_scripts/export_redux.py, which will generate a "
            "redux_data_types.txt file in its folder, or from any text file where each line specifies the data type's "
            "name and fields, separated by semi-colons; fields are specified in type-name-size tuples whose elements "
            "are separated by commas. For example:\n");
        gui->useMonoFont();
        ImGui::TextUnformatted("CdlLOC;u_char,minute,1;u_char,second,1;u_char,sector,1;u_char,track,1;\n");
        ImGui::PopFont();
        ImGui::TextUnformatted("Arrays are specified as\n");
        gui->useMonoFont();
        ImGui::TextUnformatted("type[number]\n");
        ImGui::PopFont();
        ImGui::TextUnformatted("and pointers as\n");
        gui->useMonoFont();
        ImGui::TextUnformatted("type *");
        ImGui::PopFont();
        showImportDataTypesFileDialog = ImGui::Button(_("Import data types"));
        if (showImportDataTypesFileDialog) {
            m_importDataTypesFileDialog.openDialog();
        }
        if (m_importDataTypesFileDialog.draw()) {
            std::vector<PCSX::u8string> fileToOpen = m_importDataTypesFileDialog.selected();
            if (!fileToOpen.empty()) {
                std::ifstream file(reinterpret_cast<const char*>(fileToOpen[0].c_str()));
                std::stringstream fileContents;
                fileContents << file.rdbuf();
                import(fileContents.str(), ImportType::DataTypes);
            }
        }
    }

    bool showImportFunctionsFileDialog = false;
    if (m_functions.empty()) {
        ImGui::TextWrapped(
            "Functions can be imported from Ghidra using tools/ghidra_scripts/export_redux.py, which will generate a "
            "redux_funcs.txt file in its folder, or from any text file where each line specifies the function address, "
            "name and arguments, separated by semi-colons; arguments are specified in type-name-size tuples whose "
            "elements are separated by commas. For example:\n");
        gui->useMonoFont();
        ImGui::TextUnformatted("800148b8;task_main_800148B8;int,param_1,4;int,param_2,1;\n");
        ImGui::PopFont();
        ImGui::TextUnformatted("Arrays and pointers are specified as for data types.\n");
        showImportFunctionsFileDialog = ImGui::Button(_("Import functions"));
        if (showImportFunctionsFileDialog) {
            m_importFunctionsFileDialog.openDialog();
        }
        if (m_importFunctionsFileDialog.draw()) {
            std::vector<PCSX::u8string> fileToOpen = m_importFunctionsFileDialog.selected();
            if (!fileToOpen.empty()) {
                std::ifstream file(reinterpret_cast<const char*>(fileToOpen[0].c_str()));
                std::stringstream fileContents;
                fileContents << file.rdbuf();
                import(fileContents.str(), ImportType::Functions);
            }
        }
    }

    if (m_structs.empty() || m_functions.empty()) {
        ImGui::End();
        return;
    }

    uint8_t* const memData = g_emulator->m_mem->m_psxM;
    const uint32_t memSize = 1024 * 1024 * (g_emulator->settings.get<PCSX::Emulator::Setting8MB>() ? 8 : 2);
    constexpr uint32_t memBase = 0x80000000;

    const float TEXT_BASE_WIDTH = ImGui::CalcTextSize("A").x;
    const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();

    static ImGuiTableFlags treeTableFlags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersV |
                                            ImGuiTableFlags_BordersOuterH | ImGuiTableFlags_Resizable |
                                            ImGuiTableFlags_RowBg | ImGuiTableFlags_NoBordersInBody;

    if (ImGui::BeginTabBar(_("TypedDebuggerTabBar"))) {
        if (ImGui::BeginTabItem(_("Watch"))) {
            ImGuiInputTextFlags textFlags = ImGuiInputTextFlags_CharsHexadecimal |
                                            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll |
                                            ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_CallbackAlways;

            static std::string addressInputBuffer;
            ImGui::InputText("Address##data", &addressInputBuffer, textFlags);
            unsigned int addressInputValue = 0;
            sscanf(addressInputBuffer.c_str(), "%X", &addressInputValue);

            static const char* type = nullptr;
            if (ImGui::BeginCombo("Type##combo", type)) {
                for (const auto& typeName : m_typeNames) {
                    bool isSelected = (type == typeName.c_str());
                    if (ImGui::Selectable(typeName.c_str(), isSelected)) {
                        type = typeName.c_str();
                    }
                    if (isSelected) {
                        ImGui::SetItemDefaultFocus();
                    }
                }
                ImGui::EndCombo();
            }

            static bool createArray;
            ImGui::Checkbox("Array", &createArray);

            static int numberToCreate = 1;
            if (createArray) {
                ImGui::SameLine();
                ImGui::InputInt("Number", &numberToCreate);
            } else {
                numberToCreate = 1;
            }

            ImGui::SameLine();
            if (numberToCreate > 0 && ImGui::Button("Add") && m_structs.contains(type)) {
                WatchTreeNode rootNode;
                const auto inputType = createArray ? fmt::format(f_("{}[{}]"), type, numberToCreate) : type;
                rootNode.type = inputType;
                rootNode.name = inputType;
                for (const auto& field : m_structs[type]) {
                    rootNode.size += field.size;
                }
                rootNode.size *= numberToCreate;
                populate(&rootNode, m_structs);
                m_displayedWatchData.push_back({addressInputValue, true, rootNode});
            }
            ImGui::SameLine();
            if (ImGui::Button(_("Clear"))) {
                m_displayedWatchData.clear();
                for (const auto* bp : m_watchBreakpoints) {
                    g_emulator->m_debug->removeBreakpoint(bp);
                }
                m_watchBreakpoints.clear();
            }
            if (m_watchBreakpoints.size() > 0) {
                ImGui::SameLine();
                if (ImGui::Button(_("Clear breakpoints"))) {
                    for (const auto* bp : m_watchBreakpoints) {
                        g_emulator->m_debug->removeBreakpoint(bp);
                    }
                    m_watchBreakpoints.clear();
                }
            }
            if (m_disabledInstructions.size() > 0) {
                ImGui::SameLine();
                if (ImGui::Button(_("Restore disabled instructions"))) {
                    for (const auto& instruction : m_disabledInstructions) {
                        const auto instructionAddress = instruction.first;
                        const auto& instructions = instruction.second;
                        memcpy(memData + instructionAddress - memBase, instructions.data(), 4);
                    }
                    m_disabledInstructions.clear();
                }
            }

            ImGui::Checkbox("Input in hexadecimal", &m_hex);

            gui->useMonoFont();
            if (ImGui::BeginTable(_("WatchTable"), 5, treeTableFlags)) {
                ImGui::TableSetupColumn(_("Name"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 40.0f);
                ImGui::TableSetupColumn(_("Type"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 30.0f);
                ImGui::TableSetupColumn(_("Size"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 10.0f);
                ImGui::TableSetupColumn(_("Value"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 50.0f);
                ImGui::TableSetupColumn(_("Breakpoints"), ImGuiTableColumnFlags_NoHide);
                ImGui::TableHeadersRow();

                for (auto& addressNodePair : m_displayedWatchData) {
                    displayNode(&addressNodePair.node, addressNodePair.address, true, addressNodePair.addressOfPointer);
                }

                ImGui::EndTable();
            }
            ImGui::PopFont();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem(_("Functions"))) {
            if (ImGui::Button(_("Clear log"))) {
                m_displayedFunctionData.clear();
            }
            if (m_functionBreakpoints.size() > 0) {
                ImGui::SameLine();
                if (ImGui::Button(_("Clear breakpoints"))) {
                    for (const auto* bp : m_functionBreakpoints) {
                        g_emulator->m_debug->removeBreakpoint(bp);
                    }
                    m_functionBreakpoints.clear();
                }
            }
            if (m_disabledFunctions.size() > 0) {
                ImGui::SameLine();
                if (ImGui::Button(_("Restore disabled functions"))) {
                    for (const auto& function : m_disabledFunctions) {
                        const auto functionAddress = function.first;
                        const auto& instructionsToRestore = function.second;
                        memcpy(memData + functionAddress - memBase, instructionsToRestore.data(), 8);
                    }
                    m_disabledFunctions.clear();
                }
            }

            gui->useMonoFont();
            ImVec2 outerSize{0.f, TEXT_BASE_HEIGHT * 30.f};
            if (ImGui::BeginTable(_("FunctionBreakpoints"), 5, treeTableFlags, outerSize)) {
                ImGui::TableSetupColumn(_("Name"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 40.0f);
                ImGui::TableSetupColumn(_("Type"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 30.0f);
                ImGui::TableSetupColumn(_("Size"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 10.0f);
                ImGui::TableSetupColumn(_("Value"), ImGuiTableColumnFlags_WidthFixed, TEXT_BASE_WIDTH * 50.0f);
                ImGui::TableSetupColumn(_("Breakpoints"), ImGuiTableColumnFlags_NoHide);
                ImGui::TableHeadersRow();

                for (auto& functionData : m_displayedFunctionData) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();  // Name.
                    const std::string nameColumnString =
                        fmt::format(f_("{}\t(called from {}\t@ {:#x})##{}"), functionData.functionName,
                                    functionData.callerName, functionData.callerAddress, functionData.id);
                    ImGui::TextUnformatted(nameColumnString.c_str());
                    ImGui::TableNextColumn();  // Type.
                    ImGui::TableNextColumn();  // Size.
                    ImGui::TableNextColumn();  // Value.
                    ImGui::TableNextColumn();  // Breakpoints.
                    for (auto& argData : functionData.argData) {
                        if (auto* addressNodeTuple = std::get_if<AddressNodeTuple>(&argData)) {
                            displayNode(&addressNodeTuple->node, addressNodeTuple->address, false,
                                        addressNodeTuple->addressOfPointer, functionData.id);
                        } else if (auto* registerValue = std::get_if<RegisterValue>(&argData)) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();  // Name.
                            ImGui::TreeNodeEx(registerValue->name.c_str(), ImGuiTreeNodeFlags_Leaf |
                                                                               ImGuiTreeNodeFlags_Bullet |
                                                                               ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                                                               ImGuiTreeNodeFlags_SpanFullWidth);
                            ImGui::TableNextColumn();  // Type.
                            ImGui::TextUnformatted(registerValue->type.c_str());
                            ImGui::TableNextColumn();  // Size.
                            ImGui::Text("%zu", registerValue->size);
                            ImGui::TableNextColumn();  // Value.
                            printValue(registerValue->type.c_str(), &registerValue->value, false);
                            ImGui::TableNextColumn();  // Breakpoints.
                        } else {
                            assert(false);
                        }
                    }
                    ImGui::Separator();
                }
                ImGui::EndTable();
            }
            ImGui::PopFont();

            static ImGuiTableFlags functionTableFlags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                                                        ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
                                                        ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
                                                        ImGuiTableFlags_Hideable;

            gui->useMonoFont();
            if (ImGui::BeginTable(_("Functions"), 4, functionTableFlags)) {
                ImGui::TableSetupColumn(_("Address"));
                ImGui::TableSetupColumn(_("Name"));
                ImGui::TableSetupColumn(_("Breakpoints"));
                ImGui::TableSetupColumn(_("Toggle"));
                ImGui::TableHeadersRow();

                ImGuiListClipper clipper;
                clipper.Begin(m_functionAddresses.size());
                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                        const auto currentAddress = m_functionAddresses[row];

                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("0x%2x", currentAddress);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%s", m_functions[currentAddress].name.c_str());
                        ImGui::TableSetColumnIndex(2);
                        auto breakpointButtonName = fmt::format(f_("Add breakpoint##{}"), row);
                        PCSX::Debug::BreakpointInvoker invoker = [this, memBase, memData, memSize, currentAddress](
                                                                     const PCSX::Debug::Breakpoint* self,
                                                                     uint32_t address, unsigned width,
                                                                     const char* cause) {
                            address += memBase;
                            const auto& func = m_functions[address];

                            FunctionBreakpointData bpData;
                            static uint32_t id = 0;
                            bpData.id = id++;
                            bpData.functionName = func.name;

                            const auto& regs = g_emulator->m_cpu->m_regs.GPR.n;
                            // @todo: handle arguments passed on the stack.
                            for (int i = 0; i < std::min(size_t{4}, func.arguments.size()); ++i) {
                                const auto& arg = func.arguments[i];
                                uint32_t reg_value = 0;
                                switch (i) {
                                    case 0:
                                        reg_value = regs.a0;
                                        break;
                                    case 1:
                                        reg_value = regs.a1;
                                        break;
                                    case 2:
                                        reg_value = regs.a2;
                                        break;
                                    case 3:
                                        reg_value = regs.a3;
                                        break;
                                    default:
                                        assert(false);
                                }

                                if (arg.type.back() == '*') {
                                    WatchTreeNode argNode{arg.type, arg.name, arg.size};
                                    populate(&argNode, m_structs);
                                    bpData.argData.push_back(AddressNodeTuple{reg_value, false, argNode});
                                } else {
                                    bpData.argData.push_back(RegisterValue{reg_value, arg.type, arg.name, arg.size});
                                }
                            }

                            const auto ra = g_emulator->m_cpu->m_regs.GPR.n.ra;
                            std::string callerName = getFunctionNameFromInstructionAddress(ra);
                            if (callerName.empty()) {
                                callerName = "overlay?";
                            }
                            bpData.callerName = callerName;
                            bpData.callerAddress = ra;

                            m_displayedFunctionData.push_back(bpData);

                            g_system->pause();
                            return true;
                        };
                        if (ImGui::Button(breakpointButtonName.c_str())) {
                            auto* newBreakpoint = g_emulator->m_debug->addBreakpoint(
                                currentAddress, Debug::BreakpointType::Exec, 4, _("Typed Debugger"), invoker);
                            m_functionBreakpoints.push_back(newBreakpoint);
                        }
                        ImGui::TableSetColumnIndex(3);
                        const bool functionToggledOff = m_disabledFunctions.contains(currentAddress);
                        auto toggleButtonName = functionToggledOff ? fmt::format(f_("Re-enable##{}"), row)
                                                                   : fmt::format(f_("Disable##{}"), row);
                        if (ImGui::Button(toggleButtonName.c_str())) {
                            auto* functionMem = memData + currentAddress - memBase;
                            if (functionToggledOff) {
                                memcpy(functionMem, m_disabledFunctions[currentAddress].data(), 8);
                                m_disabledFunctions.erase(currentAddress);
                            } else {
                                uint8_t instructions[8];
                                memcpy(instructions, functionMem, 8);
                                m_disabledFunctions[currentAddress] = std::to_array(instructions);
                                static constexpr uint8_t jr_ra[8] = {0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00};
                                memcpy(functionMem, jr_ra, 8);
                            }
                        }
                    }
                }
                ImGui::EndTable();
            }
            ImGui::PopFont();
            ImGui::EndTabItem();
        }
        ImGui::TreePop();
    }
    ImGui::End();
}
