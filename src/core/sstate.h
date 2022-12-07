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

#include <string_view>

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
// skip id 9
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x1000>, TYPESTRING("icache_addr"), 10> ICacheAddr;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x1000>, TYPESTRING("icache_code"), 11> ICacheCode;
// skip id 12
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("next_is_delay_slot"), 13> NextIsDelaySlot;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("index"), 1> DelaySlotIndex;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mask"), 6> DelaySlotMask;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("value"), 2> DelaySlotValue;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pc_value"), 3> DelaySlotPcValue;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("active"), 4> DelaySlotActive;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("pc_active"), 5> DelaySlotPcActive;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("from_link"), 7> DelaySlotFromLink;
typedef Protobuf::Message<TYPESTRING("DelaySlotInfo"), DelaySlotIndex, DelaySlotValue, DelaySlotMask, DelaySlotPcValue,
                          DelaySlotActive, DelaySlotPcActive, DelaySlotFromLink>
    DelaySlotInfo;
typedef Protobuf::MessageField<DelaySlotInfo, TYPESTRING("delay_slot_info_1"), 14> DelaySlotInfo1;
typedef Protobuf::MessageField<DelaySlotInfo, TYPESTRING("delay_slot_info_2"), 15> DelaySlotInfo2;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("current_delayed_load"), 16> CurrentDelayedLoad;
typedef Protobuf::RepeatedFieldRef<Protobuf::UInt32, 32, TYPESTRING("interrupt_targets"), 17> IntTargetsField;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("in_isr"), 18> InISR;
typedef Protobuf::Message<TYPESTRING("Registers"), GPR, CP0, CP2D, CP2C, PC, Code, Cycle, Interrupt, ICacheAddr,
                          ICacheCode, NextIsDelaySlot, DelaySlotInfo1, DelaySlotInfo2, CurrentDelayedLoad,
                          IntTargetsField, InISR>
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
// Capture buffer
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("cbStartInd"), 10> CBStartIndex;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("cbCurrInd"), 11> CBCurrIndex;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("cbEndInd"), 12> CBEndIndex;
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("cbVoiceInd"), 13> CBVoiceIndex;

typedef Protobuf::Field<Protobuf::FixedBytes<1024 * 16 * 2>, TYPESTRING("CBLeft"), 14> CBCDLeft;
typedef Protobuf::Field<Protobuf::FixedBytes<1024 * 16 * 2>, TYPESTRING("CBRight"), 15> CBCDRight;

typedef Protobuf::Message<TYPESTRING("SPU"), SPURam, SPUPorts, XAField, SPUIrq, SPUIrqPtr, Channels, SPUAddr, SPUCtrl,
                          SPUStat, CBStartIndex, CBCurrIndex, CBEndIndex, CBVoiceIndex, CBCDLeft, CBCDRight>
    SPU;
typedef Protobuf::MessageField<SPU, TYPESTRING("spu"), 6> SPUField;

typedef Protobuf::FieldPtr<Protobuf::FixedBytes<0x1010>, TYPESTRING("buffer"), 1> SIOBuffer;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("status_reg"), 2> SIOStatusReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mode_reg"), 3> SIOModeReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("ctrl_reg"), 4> SIOCtrlReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("baud_reg"), 5> SIOBaudReg;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("buffer_max_index"), 6> SIOBufferMaxIndex;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("buffer_index"), 7> SIOBufferIndex;
// skip id 8
// skip id 9
// skip id 10
// skip id 11
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pad_state"), 12> SIOPadState;
// skip id 13
// skip id 14
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("currentdevice"), 15> SIOCurrentDevice;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<128>, TYPESTRING("mcd1_tempbuffer"), 16> SIOMCD1TempBuffer;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd1_directoryflag"), 17> SIOMCD1DirectoryFlag;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd1_checksumin"), 18> SIOMCD1ChecksumIn;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd1_checksumout"), 19> SIOMCD1ChecksumOut;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mcd1_commandticks"), 20> SIOMCD1CommandTicks;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd1_currentcommand"), 21> SIOMCD1CurrentCommand;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mcd1_sector"), 22> SIOMCD1Sector;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mcd1_dataoffset"), 23> SIOMCD1DataOffset;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<128>, TYPESTRING("mcd2_tempbuffer"), 24> SIOMCD2TempBuffer;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd2_directoryflag"), 25> SIOMCD2DirectoryFlag;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd2_checksumin"), 26> SIOMCD2ChecksumIn;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd2_checksumout"), 27> SIOMCD2ChecksumOut;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mcd2_commandticks"), 28> SIOMCD2CommandTicks;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("mcd2_currentcommand"), 29> SIOMCD2CurrentCommand;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mcd2_sector"), 30> SIOMCD2Sector;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mcd2_dataoffset"), 31> SIOMCD2DataOffset;

typedef Protobuf::Message<TYPESTRING("SIO"), SIOBuffer, SIOStatusReg, SIOModeReg, SIOCtrlReg, SIOBaudReg,
                          SIOBufferMaxIndex, SIOBufferIndex, SIOPadState, SIOCurrentDevice, SIOMCD1TempBuffer,
                          SIOMCD1DirectoryFlag, SIOMCD1ChecksumIn, SIOMCD1ChecksumOut, SIOMCD1CommandTicks,
                          SIOMCD1CurrentCommand, SIOMCD1Sector, SIOMCD1DataOffset, SIOMCD2TempBuffer,
                          SIOMCD2DirectoryFlag, SIOMCD2ChecksumIn, SIOMCD2ChecksumOut, SIOMCD2CommandTicks,
                          SIOMCD2CurrentCommand, SIOMCD2Sector, SIOMCD2DataOffset>
    SIO;
typedef Protobuf::MessageField<SIO, TYPESTRING("sio"), 7> SIOField;
// skip id 8
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
typedef Protobuf::Field<Protobuf::Int32, TYPESTRING("spu_sync_countdown"), 3> SPUSyncCountdown;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("psx_next_counter"), 4> PSXNextCounter;
typedef Protobuf::Message<TYPESTRING("Counters"), Rcnts, HSyncCount, SPUSyncCountdown, PSXNextCounter> Counters;
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

// skip id 12

typedef Protobuf::Field<Protobuf::UInt16, TYPESTRING("fd"), 1> PCdrvFD;
typedef Protobuf::Field<Protobuf::String, TYPESTRING("filename"), 2> PCdrvFilename;
typedef Protobuf::Field<Protobuf::Bool, TYPESTRING("create"), 3> PCdrvCreate;
typedef Protobuf::Message<TYPESTRING("PCdrvFile"), PCdrvFD, PCdrvFilename, PCdrvCreate> PCdrvFile;
typedef Protobuf::RepeatedVariableField<PCdrvFile, TYPESTRING("files"), 13> PCdrvFilesField;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("ra"), 1> CallRA;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("sp"), 2> CallSP;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("sp"), 3> CallFP;
typedef Protobuf::Field<Protobuf::Bool, TYPESTRING("shadow"), 4> Shadow;
typedef Protobuf::Message<TYPESTRING("Call"), CallRA, CallSP, CallFP, Shadow> Call;

typedef Protobuf::RepeatedVariableField<Call, TYPESTRING("calls"), 1> Calls;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("low"), 2> LowSP;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("high"), 3> HighSP;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("ra"), 4> PresumedRA;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("fp"), 5> PresumedFP;
typedef Protobuf::Field<Protobuf::Bool, TYPESTRING("iscurrent"), 6> CallstackIsCurrent;
typedef Protobuf::Message<TYPESTRING("Calls"), Calls, LowSP, HighSP, PresumedRA, PresumedFP, CallstackIsCurrent>
    CallStack;

typedef Protobuf::RepeatedVariableField<CallStack, TYPESTRING("CallStacks"), 1> CallStacksMessageField;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("currentSP"), 2> CallStacksCurrentSP;
typedef Protobuf::Message<TYPESTRING("CallStacks"), CallStacksMessageField, CallStacksCurrentSP> CallStacks;
typedef Protobuf::MessageField<CallStacks, TYPESTRING("callstacks"), 14> CallStacksField;

typedef Protobuf::FieldPtr<Protobuf::FixedBytes<2352>, TYPESTRING("dataFIFO"), 1> CDDataFIFO;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<16>, TYPESTRING("paramFIFO"), 2> CDParamFIFO;
typedef Protobuf::FieldPtr<Protobuf::FixedBytes<16>, TYPESTRING("responseFIFO"), 3> CDResponseFIFO;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("dataFIFOIndex"), 4> CDDataFIFOIndex;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("dataFIFOSize"), 5> CDDataFIFOSize;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("paramFIFOSize"), 6> CDParamFIFOSize;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("responseFIFOData"), 7> CDResponseFIFOData;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("responseFIFOSize"), 8> CDResponseFIFOSize;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("registerIndex"), 9> CDRegisterIndex;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("busy"), 10> CDBusy;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("state"), 11> CDState;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("command"), 12> CDCommand;
typedef Protobuf::Message<TYPESTRING("CDRom"), CDDataFIFO, CDParamFIFO, CDResponseFIFO, CDDataFIFOIndex, CDDataFIFOSize,
                          CDParamFIFOSize, CDResponseFIFOData, CDResponseFIFOSize, CDRegisterIndex, CDBusy, CDState,
                          CDCommand>
    CDRom;
typedef Protobuf::MessageField<CDRom, TYPESTRING("cdrom"), 15> CDRomField;

typedef Protobuf::Message<TYPESTRING("SaveState"), SaveStateInfoField, ThumbnailField, MemoryField, RegistersField,
                          GPUField, SPUField, SIOField, HardwareField, CountersField, MDECField, PCdrvFilesField,
                          CallStacksField, CDRomField>
    SaveState;

typedef Protobuf::ProtoFile<SaveStateInfo, Thumbnail, Memory, DelaySlotInfo, Registers, GPU, ADPCMDecode, XA,
                            ::PCSX::SPU::Chan::Data, ::PCSX::SPU::ADSRInfo, ::PCSX::SPU::ADSRInfoEx, Channel, SPU, SIO,
                            CDRom, Hardware, Rcnt, Counters, MDEC, PCdrvFile, Call, CallStack, CallStacks, SaveState>
    ProtoFile;

SaveState constructSaveState();

std::string save();
bool load(std::string_view data);
}  // namespace SaveStates

}  // namespace PCSX
