/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "core/sstate.h"

#include "core/callstacks.h"
#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/mdec.h"
#include "core/psxcounters.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sio.h"
#include "spu/interface.h"

PCSX::SaveStates::SaveState PCSX::SaveStates::constructSaveState() {
    // clang-format off
    return SaveState {
        SaveStateInfo {
            VersionString {},
            Version {},
        },
        Thumbnail {},
        Memory {
            RAM { g_emulator->m_mem->m_psxM },
            ROM { g_emulator->m_mem->m_psxR },
            Parallel { g_emulator->m_mem->m_psxP },
            HardwareMemory { g_emulator->m_mem->m_psxH },
        },
        Registers {
            GPR { g_emulator->m_cpu->m_regs.GPR.r },
            CP0 { g_emulator->m_cpu->m_regs.CP0.r },
            CP2D { g_emulator->m_cpu->m_regs.CP2D.r },
            CP2C { g_emulator->m_cpu->m_regs.CP2C.r },
            PC { g_emulator->m_cpu->m_regs.pc },
            Code { g_emulator->m_cpu->m_regs.code },
            Cycle { g_emulator->m_cpu->m_regs.cycle },
            Interrupt { g_emulator->m_cpu->m_regs.interrupt },
            ICacheAddr { g_emulator->m_cpu->m_regs.ICache_Addr },
            ICacheCode { g_emulator->m_cpu->m_regs.ICache_Code },
            NextIsDelaySlot { g_emulator->m_cpu->m_nextIsDelaySlot },
            DelaySlotInfo1 {
                DelaySlotIndex { g_emulator->m_cpu->m_delayedLoadInfo[0].index },
                DelaySlotValue { g_emulator->m_cpu->m_delayedLoadInfo[0].value },
                DelaySlotMask { g_emulator->m_cpu->m_delayedLoadInfo[0].mask },
                DelaySlotPcValue { g_emulator->m_cpu->m_delayedLoadInfo[0].pcValue },
                DelaySlotActive { g_emulator->m_cpu->m_delayedLoadInfo[0].active },
                DelaySlotPcActive { g_emulator->m_cpu->m_delayedLoadInfo[0].pcActive },
                DelaySlotFromLink { g_emulator->m_cpu->m_delayedLoadInfo[0].fromLink }
            },
            DelaySlotInfo2 {
                DelaySlotIndex { g_emulator->m_cpu->m_delayedLoadInfo[1].index },
                DelaySlotValue { g_emulator->m_cpu->m_delayedLoadInfo[1].value },
                DelaySlotMask { g_emulator->m_cpu->m_delayedLoadInfo[1].mask },
                DelaySlotPcValue { g_emulator->m_cpu->m_delayedLoadInfo[1].pcValue },
                DelaySlotActive { g_emulator->m_cpu->m_delayedLoadInfo[1].active },
                DelaySlotPcActive { g_emulator->m_cpu->m_delayedLoadInfo[1].pcActive },
                DelaySlotFromLink { g_emulator->m_cpu->m_delayedLoadInfo[1].fromLink }
            },
            CurrentDelayedLoad { g_emulator->m_cpu->m_currentDelayedLoad },
            IntTargetsField { g_emulator->m_cpu->m_regs.intTargets },
            InISR { g_emulator->m_cpu->m_inISR },
        },
        GPU {},
        SPU {},
        SIO {
            SIOBuffer { g_emulator->m_sio->m_buffer },
            SIOStatusReg { g_emulator->m_sio->m_regs.status },
            SIOModeReg { g_emulator->m_sio->m_regs.mode },
            SIOCtrlReg { g_emulator->m_sio->m_regs.control },
            SIOBaudReg { g_emulator->m_sio->m_regs.baud },
            SIOBufferMaxIndex { g_emulator->m_sio->m_maxBufferIndex },
            SIOBufferIndex { g_emulator->m_sio->m_bufferIndex },
            SIOPadState { g_emulator->m_sio->m_padState },
            SIOCurrentDevice { g_emulator->m_sio->m_currentDevice },
            SIOMCD1TempBuffer { g_emulator->m_sio->m_memoryCard[0].m_tempBuffer },
            SIOMCD1DirectoryFlag { g_emulator->m_sio->m_memoryCard[0].m_directoryFlag },
            SIOMCD1ChecksumIn{ g_emulator->m_sio->m_memoryCard[0].m_checksumIn},
            SIOMCD1ChecksumOut{g_emulator->m_sio->m_memoryCard[0].m_checksumOut},
            SIOMCD1CommandTicks{g_emulator->m_sio->m_memoryCard[0].m_commandTicks},
            SIOMCD1CurrentCommand{g_emulator->m_sio->m_memoryCard[0].m_currentCommand},
            SIOMCD1Sector{g_emulator->m_sio->m_memoryCard[0].m_sector},
            SIOMCD1DataOffset{g_emulator->m_sio->m_memoryCard[0].m_dataOffset},
            SIOMCD2TempBuffer{g_emulator->m_sio->m_memoryCard[1].m_tempBuffer},
            SIOMCD2DirectoryFlag{g_emulator->m_sio->m_memoryCard[1].m_directoryFlag},
            SIOMCD2ChecksumIn{g_emulator->m_sio->m_memoryCard[1].m_checksumIn},
            SIOMCD2ChecksumOut{g_emulator->m_sio->m_memoryCard[1].m_checksumOut},
            SIOMCD2CommandTicks{g_emulator->m_sio->m_memoryCard[1].m_commandTicks},
            SIOMCD2CurrentCommand{g_emulator->m_sio->m_memoryCard[1].m_currentCommand},
            SIOMCD2Sector{g_emulator->m_sio->m_memoryCard[1].m_sector},
            SIOMCD2DataOffset{g_emulator->m_sio->m_memoryCard[1].m_dataOffset},
        },
        CDRom {
            CDReg1Mode { g_emulator->m_cdrom->m_reg1Mode },
            CDReg2 { g_emulator->m_cdrom->m_reg2 },
            CDCmdProcess { g_emulator->m_cdrom->m_cmdProcess },
            CDCtrl { g_emulator->m_cdrom->m_ctrl },
            CDStat { g_emulator->m_cdrom->m_stat },
            CDStatP { g_emulator->m_cdrom->m_statP },
            CDTransfer { reinterpret_cast<uint8_t*>(g_emulator->m_cdrom->m_transfer) },
            CDTransferIndex { g_emulator->m_cdrom->m_transferIndex },
            CDPrev { g_emulator->m_cdrom->m_prev.data },
            CDParam { g_emulator->m_cdrom->m_param },
            CDResult { g_emulator->m_cdrom->m_result },
            CDParamC { g_emulator->m_cdrom->m_paramC },
            CDResultC { g_emulator->m_cdrom->m_resultC },
            CDResultP { g_emulator->m_cdrom->m_resultP },
            CDResultReady { g_emulator->m_cdrom->m_resultReady },
            CDCmd { g_emulator->m_cdrom->m_cmd },
            CDRead { g_emulator->m_cdrom->m_read },
            CDSetLocPending { g_emulator->m_cdrom->m_setlocPending },
            CDReading { g_emulator->m_cdrom->m_reading },
            CDSetSectorPlay { g_emulator->m_cdrom->m_setSectorPlay.data },
            CDSetSectorEnd { g_emulator->m_cdrom->m_setSectorEnd.data },
            CDSetSector { g_emulator->m_cdrom->m_setSector.data },
            CDTrack { g_emulator->m_cdrom->m_track },
            CDPlay { g_emulator->m_cdrom->m_play },
            CDMuted { g_emulator->m_cdrom->m_muted },
            CDCurTrack { g_emulator->m_cdrom->m_curTrack },
            CDMode { g_emulator->m_cdrom->m_mode },
            CDFile { g_emulator->m_cdrom->m_file },
            CDChannel { g_emulator->m_cdrom->m_channel },
            CDSuceeded { g_emulator->m_cdrom->m_suceeded },
            CDFirstSector { g_emulator->m_cdrom->m_firstSector },
            CDIRQ { g_emulator->m_cdrom->m_irq },
            CDIrqRepeated { g_emulator->m_cdrom->m_irqRepeated },
            CDECycle { g_emulator->m_cdrom->m_eCycle },
            CDSeeked { g_emulator->m_cdrom->m_seeked },
            CDReadRescheduled { g_emulator->m_cdrom->m_readRescheduled },
            CDDriveState { g_emulator->m_cdrom->m_driveState },
            CDFastForward { g_emulator->m_cdrom->m_fastForward },
            CDFastBackward { g_emulator->m_cdrom->m_fastBackward },
            CDAttenuatorLeftToLeft { g_emulator->m_cdrom->m_attenuatorLeftToLeft },
            CDAttenuatorLeftToRight { g_emulator->m_cdrom->m_attenuatorLeftToRight },
            CDAttenuatorRightToRight { g_emulator->m_cdrom->m_attenuatorRightToRight },
            CDAttenuatorRightToLeft { g_emulator->m_cdrom->m_attenuatorRightToLeft },
            CDAttenuatorLeftToLeftT { g_emulator->m_cdrom->m_attenuatorLeftToLeftT },
            CDAttenuatorLeftToRightT { g_emulator->m_cdrom->m_attenuatorLeftToRightT },
            CDAttenuatorRightToRightT { g_emulator->m_cdrom->m_attenuatorRightToRightT },
            CDAttenuatorRightToLeftT { g_emulator->m_cdrom->m_attenuatorRightToLeftT },
            CDSubQTrack { g_emulator->m_cdrom->m_subq.track },
            CDSubQIndex { g_emulator->m_cdrom->m_subq.index },
            CDSubQRelative { g_emulator->m_cdrom->m_subq.relative },
            CDSubQAbsolute { g_emulator->m_cdrom->m_subq.absolute },
            CDTrackChanged { g_emulator->m_cdrom->m_trackChanged },
            CDLocationChanged { g_emulator->m_cdrom->m_locationChanged },
        },
        Hardware {},
        Counters {},
        MDEC {},
        PCdrvFilesField {},
        CallStacks {},
    };
    // clang-format on
}

namespace PCSX {
struct SaveStateWrapper {
    SaveStateWrapper(SaveStates::SaveState& state_) : state(state_) {}
    SaveStates::SaveState& state;
};
}  // namespace PCSX

std::string PCSX::SaveStates::save() {
    SaveState state = constructSaveState();
    SaveStateWrapper wrapper(state);

    state.get<SaveStateInfoField>().get<VersionString>().value = "PCSX-Redux SaveState v3";
    state.get<SaveStateInfoField>().get<Version>().value = 3;

    g_emulator->m_gpu->serialize(&wrapper);
    g_emulator->m_spu->save(state.get<SPUField>());

    g_emulator->m_counters->serialize(&wrapper);
    g_emulator->m_mdec->serialize(&wrapper);

    g_emulator->m_cpu->listAllPCdevFiles([&state](uint16_t fd, std::filesystem::path filename, bool create) {
        state.get<PCdrvFilesField>().value.emplace_back(fd, filename.string(), create);
    });

    g_emulator->m_callStacks->serialize(&wrapper);

    Protobuf::OutSlice slice;
    state.serialize(&slice);
    return slice.finalize();
}

void PCSX::CallStacks::serialize(SaveStateWrapper* w) {
    using namespace SaveStates;
    auto& callstacks = w->state.get<SaveStates::CallStacksField>().get<CallStacksMessageField>().value;
    for (auto& callstack : getCallstacks()) {
        SaveStates::CallStack sscallstack{};
        sscallstack.get<LowSP>().value = callstack.getLow();
        sscallstack.get<HighSP>().value = callstack.getHigh();
        sscallstack.get<PresumedRA>().value = callstack.ra;
        sscallstack.get<PresumedFP>().value = callstack.fp;
        sscallstack.get<CallstackIsCurrent>().value = &callstack == m_current;
        for (auto& call : callstack.calls) {
            sscallstack.get<Calls>().value.emplace_back(call.ra, call.sp, call.fp, call.shadow);
        }
        callstacks.emplace_back(sscallstack);
    }
    w->state.get<SaveStates::CallStacksField>().get<CallStacksCurrentSP>().value = m_currentSP;
}

static void setU32(uint8_t* ptr, uint32_t value) {
    ptr[0] = value & 0xff;
    ptr[1] = (value >> 8) & 0xff;
    ptr[2] = (value >> 16) & 0xff;
    ptr[3] = (value >> 24) & 0xff;
}

void PCSX::GPU::serialize(SaveStateWrapper* w) {
    using namespace SaveStates;
    auto& gpu = w->state.get<GPUField>();
    gpu.get<GPUStatus>() = readStatus();
    gpu.get<GPUVRam>().copyFrom(getVRAM().data<uint8_t>());
    gpu.get<GPUControl>().allocate();
    const auto control = gpu.get<GPUControl>().value;

    for (unsigned i = 0; i < 256; i++) {
        setU32(control + i * 4, m_statusControl[i]);
    }
}

void PCSX::MDEC::serialize(SaveStateWrapper* w) {
    using namespace SaveStates;
    uint8_t* base = (uint8_t*)&PCSX::g_emulator->m_mem->m_psxM[0x100000];
    auto& mdecSave = w->state.get<MDECField>();

    mdecSave.get<MDECReg0>().value = mdec.reg0;
    mdecSave.get<MDECReg1>().value = mdec.reg1;
    mdecSave.get<MDECRl>().value = reinterpret_cast<uint8_t*>(mdec.rl) - base;
    mdecSave.get<MDECRlEnd>().value = reinterpret_cast<uint8_t*>(mdec.rl_end) - base;
    mdecSave.get<MDECBlockBufferPos>().value = mdec.block_buffer_pos ? mdec.block_buffer_pos - base : 0;
    mdecSave.get<MDECBlockBuffer>().copyFrom(mdec.block_buffer);
    mdecSave.get<MDECDMAADR>().value = mdec.pending_dma1.adr;
    mdecSave.get<MDECDMABCR>().value = mdec.pending_dma1.bcr;
    mdecSave.get<MDECDMACHCR>().value = mdec.pending_dma1.chcr;
    for (unsigned i = 0; i < 64; i++) {
        mdecSave.get<MDECIQY>().value[i].value = iq_y[i];
        mdecSave.get<MDECIQUV>().value[i].value = iq_uv[i];
    }
}

void PCSX::Counters::serialize(SaveStateWrapper* w) {
    using namespace SaveStates;
    auto& counters = w->state.get<CountersField>();
    for (unsigned i = 0; i < CounterQuantity; i++) {
        counters.get<Rcnts>().value[i].get<RcntMode>().value = m_rcnts[i].mode;
        counters.get<Rcnts>().value[i].get<RcntTarget>().value = m_rcnts[i].target;
        counters.get<Rcnts>().value[i].get<RcntRate>().value = m_rcnts[i].rate;
        counters.get<Rcnts>().value[i].get<RcntIRQ>().value = m_rcnts[i].irq;
        counters.get<Rcnts>().value[i].get<RcntCounterState>().value = m_rcnts[i].counterState;
        counters.get<Rcnts>().value[i].get<RcntIRQState>().value = m_rcnts[i].irqState;
        counters.get<Rcnts>().value[i].get<RcntCycle>().value = m_rcnts[i].cycle;
        counters.get<Rcnts>().value[i].get<RcntCycleStart>().value = m_rcnts[i].cycleStart;
    }
    counters.get<HSyncCount>().value = m_hSyncCount;
    counters.get<SPUSyncCountdown>().value = m_spuSyncCountdown;
    counters.get<PSXNextCounter>().value = m_psxNextCounter;
}

bool PCSX::SaveStates::load(std::string_view data) {
    SaveState state = constructSaveState();

    Protobuf::InSlice slice(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    try {
        state.deserialize(&slice, 0);
    } catch (...) {
        return false;
    }

    if (state.get<SaveStateInfoField>().get<Version>().value != 3) {
        return false;
    }

    SaveStateWrapper wrapper(state);
    PCSX::g_emulator->m_cpu->Reset();
    state.commit();
    g_emulator->m_cpu->m_regs.lowestTarget = g_emulator->m_cpu->m_regs.cycle;
    g_emulator->m_cpu->m_regs.previousCycles = g_emulator->m_cpu->m_regs.cycle;
    // x86-64 recompiler might make save states with an unaligned PC, since it ignores the bottom 2 bits
    // So we just force-align it here, since it's never meant to be misaligned
    g_emulator->m_cpu->m_regs.pc &= ~3;
    g_emulator->m_gpu->deserialize(&wrapper);
    g_emulator->m_spu->load(state.get<SPUField>());
    g_emulator->m_cdrom->load();

    g_emulator->m_counters->deserialize(&wrapper);
    g_emulator->m_mdec->deserialize(&wrapper);

    auto& xa = state.get<SPUField>().get<SaveStates::XAField>();

    g_emulator->m_cdrom->m_xa.freq = xa.get<SaveStates::XAFrequency>().value;
    g_emulator->m_cdrom->m_xa.nbits = xa.get<SaveStates::XANBits>().value;
    g_emulator->m_cdrom->m_xa.nsamples = xa.get<SaveStates::XANSamples>().value;
    g_emulator->m_cdrom->m_xa.stereo = xa.get<SaveStates::XAStereo>().value;
    auto& left = xa.get<SaveStates::XAADPCMLeft>();
    g_emulator->m_cdrom->m_xa.left.y0 = left.get<SaveStates::ADPCMDecodeY0>().value;
    g_emulator->m_cdrom->m_xa.left.y1 = left.get<SaveStates::ADPCMDecodeY1>().value;
    auto& right = xa.get<SaveStates::XAADPCMLeft>();
    g_emulator->m_cdrom->m_xa.right.y0 = right.get<SaveStates::ADPCMDecodeY0>().value;
    g_emulator->m_cdrom->m_xa.right.y1 = right.get<SaveStates::ADPCMDecodeY1>().value;
    xa.get<SaveStates::XAPCM>().copyTo(reinterpret_cast<uint8_t*>(g_emulator->m_cdrom->m_xa.pcm));
    g_emulator->m_spu->playADPCMchannel(&g_emulator->m_cdrom->m_xa);

    g_emulator->m_cpu->closeAllPCdevFiles();
    for (auto& file : state.get<PCdrvFilesField>().value) {
        uint16_t fd = file.get<PCdrvFD>().value;
        std::string filename = file.get<PCdrvFilename>().value;
        bool create = file.get<PCdrvCreate>().value;
        if (create) {
            g_emulator->m_cpu->restorePCdrvFile(filename, fd, FileOps::CREATE);
        } else {
            g_emulator->m_cpu->restorePCdrvFile(filename, fd);
        }
    }
    g_emulator->m_callStacks->deserialize(&wrapper);

    g_system->m_eventBus->signal(Events::ExecutionFlow::SaveStateLoaded{});

    return true;
}

void PCSX::CallStacks::deserialize(const SaveStateWrapper* w) {
    using namespace SaveStates;
    m_callstacks.destroyAll();

    auto& callstacks = w->state.get<CallStacksField>().get<CallStacksMessageField>().value;
    m_current = nullptr;

    for (auto& sscallstack : callstacks) {
        auto& calls = sscallstack.get<Calls>().value;
        uint32_t lowSP = sscallstack.get<LowSP>().value;
        uint32_t highSP = sscallstack.get<HighSP>().value;
        uint32_t ra = sscallstack.get<PresumedRA>().value;
        uint32_t fp = sscallstack.get<PresumedFP>().value;
        bool isCurrent = sscallstack.get<CallstackIsCurrent>().value;
        CallStack* callstack = new CallStack();
        callstack->ra = ra;
        callstack->fp = fp;
        for (auto& call : calls) {
            uint32_t ra = call.get<CallRA>().value;
            uint32_t sp = call.get<CallSP>().value;
            uint32_t fp = call.get<CallFP>().value;
            bool shadow = call.get<Shadow>().value;
            callstack->calls.push_back(new CallStack::Call(sp, fp, ra, shadow));
        }
        if (isCurrent) m_current = callstack;
        m_callstacks.insert(lowSP, highSP, callstack);
    }

    m_currentSP = w->state.get<SaveStates::CallStacksField>().get<CallStacksCurrentSP>().value;
}

static uint32_t getU32(const uint8_t* ptr) { return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24); }

void PCSX::GPU::deserialize(const SaveStateWrapper* w) {
    using namespace SaveStates;
    reset();
    auto& gpu = w->state.get<GPUField>();
    restoreStatus(gpu.get<GPUStatus>().value);
    if (gpu.get<GPUVRam>().value) {
        partialUpdateVRAM(0, 0, 1024, 512, reinterpret_cast<const uint16_t*>(gpu.get<GPUVRam>().value));
    } else {
        clearVRAM();
    }
    const auto control = gpu.get<GPUControl>().value;

    for (unsigned i = 0; i < 256; i++) {
        m_statusControl[i] = getU32(control + i * 4);
    }

    writeStatus(m_statusControl[0]);
    writeStatus(m_statusControl[1]);
    writeStatus(m_statusControl[2]);
    writeStatus(m_statusControl[3]);
    writeStatus(m_statusControl[8]);  // try to repair things
    writeStatus(m_statusControl[6]);
    writeStatus(m_statusControl[7]);
    writeStatus(m_statusControl[5]);
    writeStatus(m_statusControl[4]);
}

void PCSX::MDEC::deserialize(const SaveStateWrapper* w) {
    using namespace SaveStates;
    uint8_t* base = (uint8_t*)&g_emulator->m_mem->m_psxM[0x100000];
    auto& mdecSave = w->state.get<MDECField>();

    mdec.reg0 = mdecSave.get<MDECReg0>().value;
    mdec.reg1 = mdecSave.get<MDECReg1>().value;
    mdec.rl = reinterpret_cast<uint16_t*>(mdecSave.get<MDECRl>().value + base);
    mdec.rl_end = reinterpret_cast<uint16_t*>(mdecSave.get<MDECRlEnd>().value + base);
    const auto& pos = mdecSave.get<MDECBlockBufferPos>().value;
    mdec.block_buffer_pos = pos ? pos + base : nullptr;
    mdecSave.get<MDECBlockBuffer>().copyTo(mdec.block_buffer);
    mdec.pending_dma1.adr = mdecSave.get<MDECDMAADR>().value;
    mdec.pending_dma1.bcr = mdecSave.get<MDECDMABCR>().value;
    mdec.pending_dma1.chcr = mdecSave.get<MDECDMACHCR>().value;
    for (unsigned i = 0; i < 64; i++) {
        iq_y[i] = mdecSave.get<MDECIQY>().value[i].value;
        iq_uv[i] = mdecSave.get<MDECIQUV>().value[i].value;
    }
}

void PCSX::Counters::deserialize(const SaveStateWrapper* w) {
    using namespace SaveStates;
    auto& counters = w->state.get<CountersField>();
    for (unsigned i = 0; i < CounterQuantity; i++) {
        m_rcnts[i].mode = counters.get<Rcnts>().value[i].get<RcntMode>().value;
        m_rcnts[i].target = counters.get<Rcnts>().value[i].get<RcntTarget>().value;
        m_rcnts[i].rate = counters.get<Rcnts>().value[i].get<RcntRate>().value;
        m_rcnts[i].irq = counters.get<Rcnts>().value[i].get<RcntIRQ>().value;
        m_rcnts[i].counterState = counters.get<Rcnts>().value[i].get<RcntCounterState>().value;
        m_rcnts[i].irqState = counters.get<Rcnts>().value[i].get<RcntIRQState>().value;
        m_rcnts[i].cycle = counters.get<Rcnts>().value[i].get<RcntCycle>().value;
        m_rcnts[i].cycleStart = counters.get<Rcnts>().value[i].get<RcntCycleStart>().value;
    }
    m_hSyncCount = counters.get<HSyncCount>().value;
    m_spuSyncCountdown = counters.get<SPUSyncCountdown>().value;
    m_psxNextCounter = counters.get<PSXNextCounter>().value;

    calculateHsync();
    // iCB: recalculate target count in case overclock is changed
    m_rcnts[3].target =
        (g_emulator->m_psxClockSpeed / (FrameRate[g_emulator->settings.get<Emulator::SettingVideo>()] *
                                        m_HSyncTotal[g_emulator->settings.get<Emulator::SettingVideo>()]));
    if (m_rcnts[1].rate != 1)
        m_rcnts[1].rate =
            (g_emulator->m_psxClockSpeed / (FrameRate[g_emulator->settings.get<Emulator::SettingVideo>()] *
                                            m_HSyncTotal[g_emulator->settings.get<Emulator::SettingVideo>()]));

    m_audioFrames = g_emulator->m_spu->getCurrentFrames();
}
