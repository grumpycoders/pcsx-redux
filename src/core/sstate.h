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

#pragma once

#include "spu/types.h"
#include "support/protobuf.h"
#include "support/settings.h"

namespace PCSX {

namespace SaveStates {

typedef Protobuf::Field<Protobuf::String, TYPESTRING("version_string"), 1> VersionString;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("version"), 2> Version;
typedef Protobuf::Message<TYPESTRING("SaveStateInfo"), VersionString, Version> SaveStateInfo;
typedef Protobuf::MessageField<SaveStateInfo, TYPESTRING("save_state_info"), 1> SaveStateInfoField;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("width"), 1> Width;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("height"), 2> Height;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("red"), 3> Red;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("green"), 4> Green;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("blue"), 5> Blue;
typedef Protobuf::Message<TYPESTRING("Thumbnail"), Width, Height, Red, Green, Blue> Thumbnail;
typedef Protobuf::MessageField<Thumbnail, TYPESTRING("thumbnail"), 2> ThumbnailField;

typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x00800000>, TYPESTRING("ram"), 1> RAM;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x00080000>, TYPESTRING("rom"), 2> ROM;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x00010000>, TYPESTRING("parallel"), 3> Parallel;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x00010000>, TYPESTRING("hardware"), 4> HardwareMemory;
typedef Protobuf::Message<TYPESTRING("Memory"), RAM, ROM, Parallel, HardwareMemory> Memory;
typedef Protobuf::MessageField<Memory, TYPESTRING("memory"), 3> MemoryField;

typedef Protobuf::RepeatedFieldRef<Protobuf::UInt32, 34, TYPESTRING("gpr"), 1> GPR;
typedef Protobuf::RepeatedFieldRef<Protobuf::UInt32, 32, TYPESTRING("cp0"), 2> CP0;
typedef Protobuf::RepeatedFieldRef<Protobuf::UInt32, 32, TYPESTRING("cp2d"), 3> CP2D;
typedef Protobuf::RepeatedFieldRef<Protobuf::UInt32, 32, TYPESTRING("cp2c"), 4> CP2C;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pc"), 5> PC;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("code"), 6> Code;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("cycle"), 7> Cycle;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("interrupt"), 8> Interrupt;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("scycle"), 1> IntSCycle;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("cycle"), 2> IntCycle;
typedef Protobuf::Message<TYPESTRING("InterruptCycles"), IntSCycle, IntCycle> IntCycles;
typedef Protobuf::RepeatedField<IntCycles, 32, TYPESTRING("interrupt_cycles"), 9> IntCyclesField;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x1000>, TYPESTRING("icache_addr"), 10> ICacheAddr;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x1000>, TYPESTRING("icache_code"), 11> ICacheCode;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("icache_valid"), 12> ICacheValid;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("next_is_delay_slot"), 13> NextIsDelaySlot;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("index"), 1> DelaySlotIndex;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mask"), 6> DelaySlotMask;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("value"), 2> DelaySlotValue;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pc_value"), 3> DelaySlotPcValue;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("active"), 4> DelaySlotActive;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("pc_active"), 5> DelaySlotPcActive;
typedef Protobuf::Message<TYPESTRING("DelaySlotInfo"), DelaySlotIndex, DelaySlotValue, DelaySlotMask, DelaySlotPcValue,
                          DelaySlotActive, DelaySlotPcActive>
    DelaySlotInfo;
typedef Protobuf::MessageField<DelaySlotInfo, TYPESTRING("delay_slot_info_1"), 14> DelaySlotInfo1;
typedef Protobuf::MessageField<DelaySlotInfo, TYPESTRING("delay_slot_info_2"), 15> DelaySlotInfo2;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("current_delayed_load"), 16> CurrentDelayedLoad;
typedef Protobuf::Message<TYPESTRING("Registers"), GPR, CP0, CP2D, CP2C, PC, Code, Cycle, Interrupt, IntCyclesField,
                          ICacheAddr, ICacheCode, ICacheValid, NextIsDelaySlot, DelaySlotInfo1, DelaySlotInfo2,
                          CurrentDelayedLoad>
    Registers;
typedef Protobuf::MessageField<Registers, TYPESTRING("registers"), 4> RegistersField;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("status"), 1> GPUStatus;
typedef Protobuf::Field<Protobuf::FixedBytes<0x400>, TYPESTRING("control"), 2> GPUControl;
typedef Protobuf::Field<Protobuf::FixedBytes<0x00100000>, TYPESTRING("vram"), 3> GPUVRam;
typedef Protobuf::Message<TYPESTRING("GPU"), GPUStatus, GPUControl, GPUVRam> GPU;
typedef Protobuf::MessageField<GPU, TYPESTRING("gpu"), 5> GPUField;

typedef Protobuf::Field<Protobuf::FixedBytes<0x80000>, TYPESTRING("ram"), 1> SPURam;
typedef Protobuf::Field<Protobuf::FixedBytes<0x200>, TYPESTRING("ports"), 2> SPUPorts;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("frequency"), 1> XAFrequency;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("nbits"), 2> XANBits;
typedef Protobuf::Field<Protobuf::Bool, TYPESTRING("stereo"), 3> XAStereo;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("nsamples"), 4> XANSamples;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("y0"), 1> ADPCMDecodeY0;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("y1"), 2> ADPCMDecodeY1;
typedef Protobuf::Message<TYPESTRING("ADPCMDecode"), ADPCMDecodeY0, ADPCMDecodeY1> ADPCMDecode;
typedef Protobuf::MessageField<ADPCMDecode, TYPESTRING("left"), 5> XAADPCMLeft;
typedef Protobuf::MessageField<ADPCMDecode, TYPESTRING("right"), 6> XAADPCMRight;
typedef Protobuf::Field<Protobuf::FixedBytes<32768>, TYPESTRING("pcm"), 7> XAPCM;
typedef Protobuf::Message<TYPESTRING("XA"), XAFrequency, XANBits, XAStereo, XANSamples, XAADPCMLeft, XAADPCMRight,
                          XAPCM>
    XA;
typedef Protobuf::MessageField<XA, TYPESTRING("xa"), 3> XAField;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("irq"), 4> SPUIrq;
typedef Protobuf::Field<Protobuf::UInt64, TYPESTRING("irqptr"), 5> SPUIrqPtr;
typedef Protobuf::MessageField<::PCSX::SPU::Chan::Data, TYPESTRING("data"), 1> Data;
typedef Protobuf::MessageField<::PCSX::SPU::ADSRInfo, TYPESTRING("adsr"), 2> ADSRInfo;
typedef Protobuf::MessageField<::PCSX::SPU::ADSRInfoEx, TYPESTRING("adsr_ex"), 3> ADSRInfoEx;
typedef Protobuf::Message<TYPESTRING("Channel"), Data, ADSRInfo, ADSRInfoEx> Channel;
typedef Protobuf::RepeatedField<Channel, 24, TYPESTRING("channel"), 6> Channels;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("addr"), 7> SPUAddr;
typedef Protobuf::Field<Protobuf::UInt16, TYPESTRING("ctrl"), 8> SPUCtrl;
typedef Protobuf::Field<Protobuf::UInt16, TYPESTRING("stat"), 9> SPUStat;
typedef Protobuf::Message<TYPESTRING("SPU"), SPURam, SPUPorts, XAField, SPUIrq, SPUIrqPtr, Channels, SPUAddr, SPUCtrl,
                          SPUStat>
    SPU;
typedef Protobuf::MessageField<SPU, TYPESTRING("spu"), 6> SPUField;

typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x1010>, TYPESTRING("buffer"), 1> SIOBuffer;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("status_reg"), 2> SIOStatusReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mode_reg"), 3> SIOModeReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("ctrl_reg"), 4> SIOCtrlReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("baud_reg"), 5> SIOBaudReg;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("buffer_max_index"), 6> SIOBufferMaxIndex;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("buffer_index"), 7> SIOBufferIndex;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mcd_state"), 8> SIOMCDState;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mcd_readwrite_state"), 9> SIOMCDReadWriteState;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd_addr_high"), 10> SIOMCDAddrHigh;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd_addr_low"), 11> SIOMCDAddrLow;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pad_state"), 12> SIOPadState;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("was_mcd1_inserted"), 13> SIOWasMCD1Inserted;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("was_mcd2_inserted"), 14> SIOWasMCD2Inserted;
typedef Protobuf::Message<TYPESTRING("SIO"), SIOBuffer, SIOStatusReg, SIOModeReg, SIOCtrlReg, SIOBaudReg,
                          SIOBufferMaxIndex, SIOBufferIndex, SIOMCDState, SIOMCDReadWriteState, SIOMCDAddrHigh,
                          SIOMCDAddrLow, SIOPadState, SIOWasMCD1Inserted, SIOWasMCD2Inserted>
    SIO;
typedef Protobuf::MessageField<SIO, TYPESTRING("sio"), 7> SIOField;

typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("ocup"), 1> CDOCUP;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("reg1_mode"), 2> CDReg1Mode;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("reg2"), 3> CDReg2;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("cmd_process"), 4> CDCmdProcess;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("ctrl"), 5> CDCtrl;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("stat"), 6> CDStat;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("stat_p"), 7> CDStatP;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<2352>, TYPESTRING("transfer"), 8> CDTransfer;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("transfer_index"), 9> CDTransferIndex;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<4>, TYPESTRING("prev"), 10> CDPrev;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<8>, TYPESTRING("param"), 11> CDParam;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<16>, TYPESTRING("result"), 12> CDResult;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("param_c"), 13> CDParamC;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("param_p"), 14> CDParamP;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("result_c"), 15> CDResultC;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("result_p"), 16> CDResultP;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("result_ready"), 17> CDResultReady;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("cmd"), 18> CDCmd;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("read"), 19> CDRead;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("set_loc_pending"), 20> CDSetLocPending;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("reading"), 21> CDReading;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<6>, TYPESTRING("result_tn"), 22> CDResultTN;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<4>, TYPESTRING("result_td"), 23> CDResultTD;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<4>, TYPESTRING("set_sector_play"), 24> CDSetSectorPlay;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<4>, TYPESTRING("set_sector_end"), 25> CDSetSectorEnd;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<4>, TYPESTRING("set_sector"), 26> CDSetSector;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("track"), 27> CDTrack;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("play"), 28> CDPlay;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("muted"), 29> CDMuted;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("cur_track"), 30> CDCurTrack;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("mode"), 31> CDMode;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("file"), 32> CDFile;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("channel"), 33> CDChannel;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("suceeded"), 34> CDSuceeded;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("first_sector"), 35> CDFirstSector;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("irq"), 36> CDIRQ;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("irq_repeated"), 37> CDIrqRepeated;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("e_cycle"), 38> CDECycle;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("seeked"), 39> CDSeeked;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("read_scheduled"), 40> CDReadRescheduled;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("drive_state"), 41> CDDriveState;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("fast_forward"), 42> CDFastForward;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("fast_backward"), 43> CDFastBackward;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_left"), 44> CDAttenuatorLeftToLeft;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_right"), 45> CDAttenuatorLeftToRight;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_right"), 46> CDAttenuatorRightToRight;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_left"), 47> CDAttenuatorRightToLeft;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_left_t"), 48> CDAttenuatorLeftToLeftT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_right_t"), 49> CDAttenuatorLeftToRightT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_right_t"), 50> CDAttenuatorRightToRightT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_left_t"), 51> CDAttenuatorRightToLeftT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("subq_track"), 52> CDSubQTrack;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("subq_index"), 53> CDSubQIndex;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<3>, TYPESTRING("subq_relative"), 54> CDSubQRelative;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<3>, TYPESTRING("subq_absolute"), 55> CDSubQAbsolute;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("track_changed"), 56> CDTrackChanged;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("location_changed"), 57> CDLocationChanged;

typedef Protobuf::Message<
    TYPESTRING("CDRom"), CDOCUP, CDReg1Mode, CDReg2, CDCmdProcess, CDCtrl, CDStat, CDStatP, CDTransfer, CDTransferIndex,
    CDPrev, CDParam, CDResult, CDParamC, CDParamP, CDResultC, CDResultP, CDResultReady, CDCmd, CDRead, CDSetLocPending,
    CDReading, CDResultTN, CDResultTD, CDSetSectorPlay, CDSetSectorEnd, CDSetSector, CDTrack, CDPlay, CDMuted,
    CDCurTrack, CDMode, CDFile, CDChannel, CDSuceeded, CDFirstSector, CDIRQ, CDIrqRepeated, CDECycle, CDSeeked,
    CDReadRescheduled, CDDriveState, CDFastForward, CDFastBackward, CDAttenuatorLeftToLeft, CDAttenuatorLeftToRight,
    CDAttenuatorRightToRight, CDAttenuatorRightToLeft, CDAttenuatorLeftToLeftT, CDAttenuatorLeftToRightT,
    CDAttenuatorRightToRightT, CDAttenuatorRightToLeftT, CDSubQTrack, CDSubQIndex, CDSubQRelative, CDSubQAbsolute,
    CDTrackChanged, CDLocationChanged>
    CDRom;
typedef Protobuf::MessageField<CDRom, TYPESTRING("cdrom"), 8> CDRomField;

typedef Protobuf::EmptyMessage<TYPESTRING("Hardware")> Hardware;
typedef Protobuf::MessageField<Hardware, TYPESTRING("hardware"), 9> HardwareField;

typedef Protobuf::Field<Protobuf::UInt16, TYPESTRING("mode"), 1> RcntMode;
typedef Protobuf::Field<Protobuf::UInt16, TYPESTRING("target"), 2> RcntTarget;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("rate"), 3> RcntRate;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("irq"), 4> RcntIRQ;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("counter_state"), 5> RcntCounterState;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("irq_state"), 6> RcntIRQState;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("cycle"), 7> RcntCycle;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("cycle_start"), 8> RcntCycleStart;
typedef Protobuf::Message<TYPESTRING("Rcnt"), RcntMode, RcntTarget, RcntRate, RcntIRQ, RcntCounterState, RcntIRQState,
                          RcntCycle, RcntCycleStart>
    Rcnt;
typedef Protobuf::RepeatedField<Rcnt, 4, TYPESTRING("rcnts"), 1> Rcnts;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("hsync_count"), 2> HSyncCount;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("spu_sync_count"), 3> SPUSyncCount;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("psx_next_counter"), 4> PSXNextCounter;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("psx_nexts_counter"), 5> PSXNextsCounter;
typedef Protobuf::Message<TYPESTRING("Counters"), Rcnts, HSyncCount, SPUSyncCount, PSXNextCounter, PSXNextsCounter>
    Counters;
typedef Protobuf::MessageField<Counters, TYPESTRING("counters"), 10> CountersField;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("reg0"), 1> MDECReg0;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("reg1"), 2> MDECReg1;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("rl"), 3> MDECRl;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("rl_end"), 4> MDECRlEnd;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("block_buffer_pos"), 5> MDECBlockBufferPos;
typedef Protobuf::Field<Protobuf::FixedBytes<768>, TYPESTRING("block_buffer"), 6> MDECBlockBuffer;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("adr"), 7> MDECDMAADR;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("bcr"), 8> MDECDMABCR;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("chcr"), 9> MDECDMACHCR;
typedef Protobuf::RepeatedField<Protobuf::Int32, 64, TYPESTRING("iq_y"), 10> MDECIQY;
typedef Protobuf::RepeatedField<Protobuf::Int32, 64, TYPESTRING("iq_uv"), 11> MDECIQUV;
typedef Protobuf::Message<TYPESTRING("MDEC"), MDECReg0, MDECReg1, MDECRl, MDECRlEnd, MDECBlockBufferPos,
                          MDECBlockBuffer, MDECDMAADR, MDECDMABCR, MDECDMACHCR, MDECIQY, MDECIQUV>
    MDEC;
typedef Protobuf::MessageField<MDEC, TYPESTRING("mdec"), 11> MDECField;

// skip id 12, next id = 13

typedef Protobuf::Message<TYPESTRING("SaveState"), SaveStateInfoField, ThumbnailField, MemoryField, RegistersField,
                          GPUField, SPUField, SIOField, CDRomField, HardwareField, CountersField, MDECField>
    SaveState;

typedef Protobuf::ProtoFile<SaveStateInfo, Thumbnail, Memory, IntCycles, DelaySlotInfo, Registers, GPU, ADPCMDecode, XA,
                            ::PCSX::SPU::Chan::Data, ::PCSX::SPU::ADSRInfo, ::PCSX::SPU::ADSRInfoEx, Channel, SPU, SIO,
                            CDRom, Hardware, Rcnt, Counters, MDEC, SaveState>
    ProtoFile;

SaveState constructSaveState();

std::string save();
bool load(const std::string& data);
}  // namespace SaveStates

}  // namespace PCSX
