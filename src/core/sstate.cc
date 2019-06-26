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
#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/mdec.h"
#include "core/psxbios.h"
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
            Version {}
        },
        Thumbnail {},
        Memory {
            RAM { g_emulator.m_psxMem->g_psxM },
            ROM { g_emulator.m_psxMem->g_psxR },
            Parallel { g_emulator.m_psxMem->g_psxP },
            HardwareMemory { g_emulator.m_psxMem->g_psxH }
        },
        Registers {
            GPR { g_emulator.m_psxCpu->m_psxRegs.GPR.r },
            CP0 { g_emulator.m_psxCpu->m_psxRegs.CP0.r },
            CP2D { g_emulator.m_psxCpu->m_psxRegs.CP2D.r },
            CP2C { g_emulator.m_psxCpu->m_psxRegs.CP2C.r },
            PC { g_emulator.m_psxCpu->m_psxRegs.pc },
            Code { g_emulator.m_psxCpu->m_psxRegs.code },
            Cycle { g_emulator.m_psxCpu->m_psxRegs.cycle },
            Interrupt { g_emulator.m_psxCpu->m_psxRegs.interrupt },
            IntCyclesField {},
            ICacheAddr { g_emulator.m_psxCpu->m_psxRegs.ICache_Addr },
            ICacheCode { g_emulator.m_psxCpu->m_psxRegs.ICache_Code },
            ICacheValid { g_emulator.m_psxCpu->m_psxRegs.ICache_valid }
        },
        GPU {},
        SPU {},
        SIO {
            SIOBuf { g_emulator.m_sio->s_buf },
            SIOStatReg { g_emulator.m_sio->s_statReg },
            SIOModeReg { g_emulator.m_sio->s_modeReg },
            SIOCtrlReg { g_emulator.m_sio->s_ctrlReg },
            SIOBaudReg { g_emulator.m_sio->s_baudReg },
            SIOBufCount { g_emulator.m_sio->s_bufcount },
            SIOParP { g_emulator.m_sio->s_parp },
            SIOMCDSt { g_emulator.m_sio->s_mcdst },
            SIORDWR { g_emulator.m_sio->s_rdwr },
            SIOAdrH { g_emulator.m_sio->s_adrH },
            SIOAdrL { g_emulator.m_sio->s_adrL },
            SIOPadSt { g_emulator.m_sio->s_padst },
        },
        CDRom {
            CDOCUP { g_emulator.m_cdrom->m_OCUP },
            CDReg1Mode { g_emulator.m_cdrom->m_Reg1Mode },
            CDReg2 { g_emulator.m_cdrom->m_Reg2 },
            CDCmdProcess { g_emulator.m_cdrom->m_CmdProcess },
            CDCtrl { g_emulator.m_cdrom->m_Ctrl },
            CDStat { g_emulator.m_cdrom->m_Stat },
            CDStatP { g_emulator.m_cdrom->m_StatP },
            CDTransfer { reinterpret_cast<uint8_t*>(g_emulator.m_cdrom->m_Transfer) },
            CDTransferIndex { g_emulator.m_cdrom->m_transferIndex },
            CDPrev { g_emulator.m_cdrom->m_Prev },
            CDParam { g_emulator.m_cdrom->m_Param },
            CDResult { g_emulator.m_cdrom->m_Result },
            CDParamC { g_emulator.m_cdrom->m_ParamC },
            CDParamP { g_emulator.m_cdrom->m_ParamP },
            CDResultC { g_emulator.m_cdrom->m_ResultC },
            CDResultP { g_emulator.m_cdrom->m_ResultP },
            CDResultReady { g_emulator.m_cdrom->m_ResultReady },
            CDCmd { g_emulator.m_cdrom->m_Cmd },
            CDRead { g_emulator.m_cdrom->m_Read },
            CDSetLocPending { g_emulator.m_cdrom->m_SetlocPending },
            CDReading { g_emulator.m_cdrom->m_Reading },
            CDResultTN { g_emulator.m_cdrom->m_ResultTN },
            CDResultTD { g_emulator.m_cdrom->m_ResultTD },
            CDSetSectorPlay { g_emulator.m_cdrom->m_SetSectorPlay },
            CDSetSectorEnd { g_emulator.m_cdrom->m_SetSectorEnd },
            CDSetSector { g_emulator.m_cdrom->m_SetSector },
            CDTrack { g_emulator.m_cdrom->m_Track },
            CDPlay { g_emulator.m_cdrom->m_Play },
            CDMuted { g_emulator.m_cdrom->m_Muted },
            CDCurTrack { g_emulator.m_cdrom->m_CurTrack },
            CDMode { g_emulator.m_cdrom->m_Mode },
            CDFile { g_emulator.m_cdrom->m_File },
            CDChannel { g_emulator.m_cdrom->m_Channel },
            CDSuceeded { g_emulator.m_cdrom->m_suceeded },
            CDFirstSector { g_emulator.m_cdrom->m_FirstSector },
            CDIRQ { g_emulator.m_cdrom->m_Irq },
            CDIrqRepeated { g_emulator.m_cdrom->m_IrqRepeated },
            CDECycle { g_emulator.m_cdrom->m_eCycle },
            CDSeeked { g_emulator.m_cdrom->m_Seeked },
            CDReadRescheduled { g_emulator.m_cdrom->m_ReadRescheduled },
            CDDriveState { g_emulator.m_cdrom->m_DriveState },
            CDFastForward { g_emulator.m_cdrom->m_FastForward },
            CDFastBackward { g_emulator.m_cdrom->m_FastBackward },
            CDAttenuatorLeftToLeft { g_emulator.m_cdrom->m_AttenuatorLeftToLeft },
            CDAttenuatorLeftToRight { g_emulator.m_cdrom->m_AttenuatorLeftToRight },
            CDAttenuatorRightToRight { g_emulator.m_cdrom->m_AttenuatorRightToRight },
            CDAttenuatorRightToLeft { g_emulator.m_cdrom->m_AttenuatorRightToLeft },
            CDAttenuatorLeftToLeftT { g_emulator.m_cdrom->m_AttenuatorLeftToLeftT },
            CDAttenuatorLeftToRightT { g_emulator.m_cdrom->m_AttenuatorLeftToRightT },
            CDAttenuatorRightToRightT { g_emulator.m_cdrom->m_AttenuatorRightToRightT },
            CDAttenuatorRightToLeftT { g_emulator.m_cdrom->m_AttenuatorRightToLeftT },
            CDSubQTrack { g_emulator.m_cdrom->m_subq.Track },
            CDSubQIndex { g_emulator.m_cdrom->m_subq.Index },
            CDSubQRelative { g_emulator.m_cdrom->m_subq.Relative },
            CDSubQAbsolute { g_emulator.m_cdrom->m_subq.Absolute },
            CDTrackChanged { g_emulator.m_cdrom->m_TrackChanged }
        },
        Hardware {},
        Counters {},
        MDEC {},
        BiosHLEField {},
    };
    // clang-format on
}

static void intCyclesFromState(const PCSX::SaveStates::SaveState& state) {
    auto& intCyclesState = state.get<PCSX::SaveStates::RegistersField>().get<PCSX::SaveStates::IntCyclesField>();
    auto& intCycles = PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle;
    for (unsigned i = 0; i < 32; i++) {
        intCycles[i].sCycle = intCyclesState.value[i].get<PCSX::SaveStates::IntSCycle>().value;
        intCycles[i].cycle = intCyclesState.value[i].get<PCSX::SaveStates::IntCycle>().value;
    }
}

static void intCyclesToState(PCSX::SaveStates::SaveState& state) {
    auto& intCyclesState = state.get<PCSX::SaveStates::RegistersField>().get<PCSX::SaveStates::IntCyclesField>();
    auto& intCycles = PCSX::g_emulator.m_psxCpu->m_psxRegs.intCycle;
    intCyclesState.value.resize(32);
    for (unsigned i = 0; i < 32; i++) {
        intCyclesState.value[i].get<PCSX::SaveStates::IntSCycle>().value = intCycles[i].sCycle;
        intCyclesState.value[i].get<PCSX::SaveStates::IntCycle>().value = intCycles[i].cycle;
    }
}

std::string PCSX::SaveStates::save() {
    SaveState state = constructSaveState();

    state.get<SaveStateInfoField>().get<VersionString>().value = "PCSX-Redux SaveState v1";
    state.get<SaveStateInfoField>().get<Version>().value = 1;

    intCyclesToState(state);
    g_emulator.m_gpu->save(state.get<GPUField>());
    g_emulator.m_spu->save(state.get<SPUField>());

    g_emulator.m_psxCounters->save(state.get<CountersField>());
    g_emulator.m_mdec->save(state.get<MDECField>());
    g_emulator.m_psxBios->save(state.get<BiosHLEField>());

    Protobuf::OutSlice slice;
    state.serialize(&slice);
    return slice.finalize();
}

bool PCSX::SaveStates::load(const std::string& data) {
    SaveState state = constructSaveState();

    Protobuf::InSlice slice(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    try {
        state.deserialize(&slice, 0);
    } catch (...) {
        return false;
    }

    if (state.get<SaveStateInfoField>().get<Version>().value != 1) {
        return false;
    }

    PCSX::g_emulator.m_psxCpu->Reset();
    state.commit();
    intCyclesFromState(state);
    g_emulator.m_gpu->load(state.get<GPUField>());
    g_emulator.m_spu->load(state.get<SPUField>());
    g_emulator.m_cdrom->load();

    g_emulator.m_psxCounters->load(state.get<CountersField>());
    g_emulator.m_mdec->load(state.get<MDECField>());
    g_emulator.m_psxBios->load(state.get<BiosHLEField>());

    auto& xa = state.get<SPUField>().get<SaveStates::XAField>();

    g_emulator.m_cdrom->m_Xa.freq = xa.get<SaveStates::XAFrequency>().value;
    g_emulator.m_cdrom->m_Xa.nbits = xa.get<SaveStates::XANBits>().value;
    g_emulator.m_cdrom->m_Xa.nsamples = xa.get<SaveStates::XANSamples>().value;
    g_emulator.m_cdrom->m_Xa.stereo = xa.get<SaveStates::XAStereo>().value;
    auto& left = xa.get<SaveStates::XAADPCMLeft>();
    g_emulator.m_cdrom->m_Xa.left.y0 = left.get<SaveStates::ADPCMDecodeY0>().value;
    g_emulator.m_cdrom->m_Xa.left.y1 = left.get<SaveStates::ADPCMDecodeY1>().value;
    auto& right = xa.get<SaveStates::XAADPCMLeft>();
    g_emulator.m_cdrom->m_Xa.right.y0 = right.get<SaveStates::ADPCMDecodeY0>().value;
    g_emulator.m_cdrom->m_Xa.right.y1 = right.get<SaveStates::ADPCMDecodeY1>().value;
    xa.get<SaveStates::XAPCM>().copyTo(reinterpret_cast<uint8_t*>(g_emulator.m_cdrom->m_Xa.pcm));
    g_emulator.m_spu->playADPCMchannel(&g_emulator.m_cdrom->m_Xa);

    return true;
}
