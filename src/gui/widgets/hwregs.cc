/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "gui/widgets/hwregs.h"

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "imgui.h"

static constexpr std::string_view irqName(unsigned n) {
    switch (n) {
        case 0:
            return "VBLANK";
        case 1:
            return "GPU";
        case 2:
            return "CDROM";
        case 3:
            return "DMA";
        case 4:
            return "TIMER0";
        case 5:
            return "TIMER1";
        case 6:
            return "TIMER2";
        case 7:
            return "CONTROLLER";
        case 8:
            return "SIO";
        case 9:
            return "SPU";
        case 10:
            return "PIO";
        default:
            return "UNKNOWN";
    }
}

static constexpr std::string_view dmaName(unsigned n) {
    switch (n) {
        case 0:
            return "MDECin";
        case 1:
            return "MDECout";
        case 2:
            return "GPU";
        case 3:
            return "CDROM";
        case 4:
            return "SPU";
        case 5:
            return "PIO";
        case 6:
            return "OTC";
        default:
            return "UNKNOWN";
    }
}

static constexpr const char* dmaSyncMode(unsigned mode) {
    switch (mode) {
        case 0:
            return "Burst";
        case 1:
            return "Slice";
        case 2:
            return "Linked-list";
        case 3:
            return "Reserved";
        default:
            return "?";
    }
}

static constexpr const char* timerClockSource(unsigned timer, unsigned src) {
    if (timer == 0) {
        switch (src & 1) {
            case 0:
                return "System clock";
            case 1:
                return "Dot clock";
        }
    } else if (timer == 1) {
        switch (src & 1) {
            case 0:
                return "System clock";
            case 1:
                return "HBlank";
        }
    } else {
        switch (src & 1) {
            case 0:
                return "System clock";
            case 1:
                return "System clock / 8";
        }
    }
    return "?";
}

static uint32_t readHWReg32(PCSX::Memory* memory, uint16_t offset) {
    uint32_t* ptr = (uint32_t*)&memory->m_hard[offset];
    return *ptr;
}

void PCSX::Widgets::HWRegs::draw(PCSX::GUI* gui, PCSX::Memory* memory, const char* title) {
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(420, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    gui->useMonoFont();

    // IRQ registers
    {
        uint32_t istat = readHWReg32(memory, Memory::ISTAT);
        uint32_t imask = readHWReg32(memory, Memory::IMASK);
        std::string istatStr = fmt::format("I_STAT: {:08x}###ISTAT", istat);
        if (ImGui::CollapsingHeader(istatStr.c_str())) {
            ImGui::Indent();
            for (unsigned i = 0; i < 11; i++) {
                bool enabled = istat & (1 << i);
                std::string label = fmt::format("{}##istat{}", irqName(i), i);
                if (ImGui::Checkbox(label.c_str(), &enabled)) {
                    uint32_t bit = 1 << i;
                    istat = enabled ? (istat | bit) : (istat & ~bit);
                    memory->writeHardwareRegister<Memory::ISTAT>(istat);
                }
            }
            ImGui::Unindent();
        }
        std::string imaskStr = fmt::format("I_MASK: {:08x}###IMASK", imask);
        if (ImGui::CollapsingHeader(imaskStr.c_str())) {
            ImGui::Indent();
            for (unsigned i = 0; i < 11; i++) {
                bool enabled = imask & (1 << i);
                std::string label = fmt::format("{}##imask{}", irqName(i), i);
                if (ImGui::Checkbox(label.c_str(), &enabled)) {
                    uint32_t bit = 1 << i;
                    imask = enabled ? (imask | bit) : (imask & ~bit);
                    memory->writeHardwareRegister<Memory::IMASK>(imask);
                }
            }
            ImGui::Unindent();
        }
    }

    ImGui::Separator();

    // DMA registers
    {
        uint32_t dpcr = readHWReg32(memory, Memory::DMA_PCR);
        std::string dpcrStr = fmt::format("DPCR: {:08x}###DPCR", dpcr);
        if (ImGui::CollapsingHeader(dpcrStr.c_str())) {
            ImGui::Indent();
            for (unsigned i = 0; i < 7; i++) {
                unsigned priority = (dpcr >> (i * 4)) & 0x7;
                bool enabled = (dpcr >> (i * 4 + 3)) & 0x1;
                ImGui::Text("%7s: pri=%u", dmaName(i).data(), priority);
                ImGui::SameLine();
                std::string checkboxStr = fmt::format("En###dpcr_en{}", i);
                if (ImGui::Checkbox(checkboxStr.c_str(), &enabled)) {
                    uint32_t bit = 1 << (i * 4 + 3);
                    dpcr = enabled ? (dpcr | bit) : (dpcr & ~bit);
                    memory->writeHardwareRegister<Memory::DMA_PCR>(dpcr);
                }
            }
            ImGui::Text("    CPU: pri=%u", (dpcr >> 28) & 0x7);
            ImGui::Unindent();
        }

        uint32_t dicr = readHWReg32(memory, Memory::DMA_ICR);
        std::string dicrStr = fmt::format("DICR: {:08x}###DICR", dicr);
        if (ImGui::CollapsingHeader(dicrStr.c_str())) {
            ImGui::Indent();
            bool busError = (dicr >> 15) & 1;
            ImGui::Checkbox(_("Bus Error###dicr_buserr"), &busError);
            bool masterEnable = (dicr >> 23) & 1;
            ImGui::Checkbox(_("Master IRQ Enable###dicr_master_en"), &masterEnable);
            bool masterFlag = (dicr >> 31) & 1;
            ImGui::Checkbox(_("Master IRQ Flag###dicr_master_flag"), &masterFlag);
            for (unsigned i = 0; i < 7; i++) {
                std::string nodeStr = fmt::format("{}###dicr_ch{}", dmaName(i), i);
                if (ImGui::TreeNode(nodeStr.c_str())) {
                    bool completion = (dicr >> i) & 1;
                    ImGui::Checkbox(_("Completion###dicr_comp"), &completion);
                    bool mask = (dicr >> (i + 16)) & 1;
                    ImGui::Checkbox(_("IRQ Enable###dicr_irq_en"), &mask);
                    bool triggered = (dicr >> (i + 24)) & 1;
                    ImGui::Checkbox(_("Triggered###dicr_trig"), &triggered);
                    ImGui::TreePop();
                }
            }
            ImGui::Unindent();
        }

        // Per-channel DMA registers
        for (unsigned ch = 0; ch < 7; ch++) {
            uint16_t base = Memory::DMA_BASE + ch * 0x10;
            uint32_t madr = readHWReg32(memory, base + Memory::DMA_MADR);
            uint32_t bcr = readHWReg32(memory, base + Memory::DMA_BCR);
            uint32_t chcr = readHWReg32(memory, base + Memory::DMA_CHCR);

            std::string chStr =
                fmt::format("DMA{} {}: MADR={:06x} BCR={:08x} CHCR={:08x}###dma_ch{}", ch, dmaName(ch), madr & 0xffffff, bcr, chcr, ch);
            if (ImGui::CollapsingHeader(chStr.c_str())) {
                ImGui::Indent();
                ImGui::Text("MADR: %08x (addr=%06x)", madr, madr & 0x1ffffc);
                uint16_t blockSize = bcr & 0xffff;
                uint16_t blockCount = (bcr >> 16) & 0xffff;
                ImGui::Text("BCR : %08x (size=%u, count=%u, total=%u words)", bcr, blockSize, blockCount,
                            blockSize * (blockCount ? blockCount : 1));
                bool active = (chcr >> 24) & 1;
                bool trigger = (chcr >> 28) & 1;
                unsigned direction = chcr & 1;
                unsigned step = (chcr >> 1) & 1;
                unsigned syncMode = (chcr >> 9) & 3;
                ImGui::Text("CHCR: %08x", chcr);
                ImGui::Text("  Direction : %s", direction ? "From RAM" : "To RAM");
                ImGui::Text("  Step      : %s", step ? "Backward (-4)" : "Forward (+4)");
                ImGui::Text("  Sync mode : %s (%u)", dmaSyncMode(syncMode), syncMode);
                ImGui::Text("  Active    : %s", active ? "Yes" : "No");
                ImGui::Text("  Trigger   : %s", trigger ? "Yes" : "No");
                ImGui::Unindent();
            }
        }
    }

    ImGui::Separator();

    // Timer registers
    {
        for (unsigned t = 0; t < 3; t++) {
            uint16_t base = 0x1100 + t * 0x10;
            uint32_t count = readHWReg32(memory, base);
            uint32_t mode = readHWReg32(memory, base + 4);
            uint32_t target = readHWReg32(memory, base + 8);

            std::string timerStr =
                fmt::format("Timer {}: count={:04x} mode={:04x} target={:04x}###timer{}", t, count & 0xffff, mode & 0xffff, target & 0xffff, t);
            if (ImGui::CollapsingHeader(timerStr.c_str())) {
                ImGui::Indent();
                ImGui::Text("Count : %04x (%u)", count & 0xffff, count & 0xffff);
                ImGui::Text("Target: %04x (%u)", target & 0xffff, target & 0xffff);
                ImGui::Text("Mode  : %04x", mode & 0xffff);
                bool syncEnable = mode & 1;
                unsigned syncMode = (mode >> 1) & 3;
                bool resetOnTarget = (mode >> 3) & 1;
                bool irqOnTarget = (mode >> 4) & 1;
                bool irqOnOverflow = (mode >> 5) & 1;
                bool irqRepeat = (mode >> 6) & 1;
                bool irqToggle = (mode >> 7) & 1;
                unsigned clockSrc = (mode >> 8) & 3;
                bool irqRequest = (mode >> 10) & 1;
                bool reachedTarget = (mode >> 11) & 1;
                bool reachedOverflow = (mode >> 12) & 1;
                ImGui::Text("  Sync enable  : %s", syncEnable ? "Yes" : "No");
                if (syncEnable) {
                    ImGui::Text("  Sync mode    : %u", syncMode);
                }
                ImGui::Text("  Clock source : %s", timerClockSource(t, clockSrc));
                ImGui::Text("  Reset on tgt : %s", resetOnTarget ? "Yes" : "No");
                ImGui::Text("  IRQ on target: %s", irqOnTarget ? "Yes" : "No");
                ImGui::Text("  IRQ on ovflw : %s", irqOnOverflow ? "Yes" : "No");
                ImGui::Text("  IRQ repeat   : %s", irqRepeat ? "Yes" : "No");
                ImGui::Text("  IRQ toggle   : %s", irqToggle ? "Yes" : "No");
                ImGui::Text("  IRQ request  : %s", irqRequest ? "No (bit10=1)" : "Yes (bit10=0)");
                ImGui::Text("  Reached tgt  : %s", reachedTarget ? "Yes" : "No");
                ImGui::Text("  Reached ovflw: %s", reachedOverflow ? "Yes" : "No");
                ImGui::Unindent();
            }
        }
    }

    ImGui::Separator();

    // Memory control registers
    {
        uint32_t exp1Base = readHWReg32(memory, 0x1000);
        uint32_t exp2Base = readHWReg32(memory, 0x1004);
        uint32_t exp1Delay = readHWReg32(memory, 0x1008);
        uint32_t exp3Delay = readHWReg32(memory, 0x100c);
        uint32_t biosRomDelay = readHWReg32(memory, 0x1010);
        uint32_t spuDelay = readHWReg32(memory, 0x1014);
        uint32_t cdromDelay = readHWReg32(memory, 0x1018);
        uint32_t exp2Delay = readHWReg32(memory, 0x101c);
        uint32_t commonDelay = readHWReg32(memory, 0x1020);
        uint32_t ramSize = readHWReg32(memory, 0x1060);
        std::string memStr = fmt::format("Memory Control###memctrl");
        if (ImGui::CollapsingHeader(memStr.c_str())) {
            ImGui::Indent();
            ImGui::Text("EXP1 Base     : %08x", exp1Base);
            ImGui::Text("EXP2 Base     : %08x", exp2Base);
            ImGui::Text("EXP1 Delay    : %08x", exp1Delay);
            ImGui::Text("EXP3 Delay    : %08x", exp3Delay);
            ImGui::Text("BIOS ROM Delay: %08x", biosRomDelay);
            ImGui::Text("SPU Delay     : %08x", spuDelay);
            ImGui::Text("CDROM Delay   : %08x", cdromDelay);
            ImGui::Text("EXP2 Delay    : %08x", exp2Delay);
            ImGui::Text("Common Delay  : %08x", commonDelay);
            ImGui::Text("RAM Size      : %08x", ramSize);
            ImGui::Unindent();
        }
    }

    ImGui::PopFont();
    ImGui::End();
}
