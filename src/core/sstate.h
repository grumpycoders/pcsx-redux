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

#include "core/protobuf.h"
#include "main/settings.h"
#include "spu/types.h"

namespace PCSX {

namespace SaveStates {
typedef Protobuf::Field<Protobuf::String, TYPESTRING("version_string"), 1> VersionString;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("version"), 2> Version;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("width"), 1> Width;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("height"), 2> Height;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("red"), 3> Red;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("green"), 4> Green;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("blue"), 5> Blue;
typedef Protobuf::Message<TYPESTRING("Thumbnail"), Width, Height, Red, Green, Blue> Thumbnail;
typedef Protobuf::MessageField<Thumbnail, TYPESTRING("thumbnail"), 3> ThumbnailField;

typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x00200000>, TYPESTRING("ram"), 1> RAM;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x00080000>, TYPESTRING("rom"), 2> ROM;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x00010000>, TYPESTRING("parallel"), 3> Parallel;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x00010000>, TYPESTRING("hardware"), 4> Hardware;
typedef Protobuf::Message<TYPESTRING("Memory"), RAM, ROM, Parallel, Hardware> Memory;
typedef Protobuf::MessageField<Memory, TYPESTRING("memory"), 4> MemoryField;

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
typedef Protobuf::RepeatedField<IntCycles, 2, TYPESTRING("interrupt_cycles"), 9> IntCyclesField;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x1000>, TYPESTRING("icache_addr"), 10> ICacheAddr;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x1000>, TYPESTRING("icache_code"), 11> ICacheCode;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("icache_valid"), 12> ICacheValid;
typedef Protobuf::Message<TYPESTRING("Registers"), GPR, CP0, CP2D, CP2C, PC, Code, Cycle, Interrupt, IntCyclesField,
                          ICacheAddr, ICacheCode, ICacheValid>
    Registers;
typedef Protobuf::MessageField<Registers, TYPESTRING("registers"), 5> RegistersField;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("status"), 1> GPUStatus;
typedef Protobuf::Field<Protobuf::FixedBytes<0x400>, TYPESTRING("control"), 2> GPUControl;
typedef Protobuf::Field<Protobuf::FixedBytes<0x00100000>, TYPESTRING("vram"), 3> GPUVRam;
typedef Protobuf::Message<TYPESTRING("GPU"), GPUStatus, GPUControl, GPUVRam> GPU;
typedef Protobuf::MessageField<GPU, TYPESTRING("gpu"), 6> GPUField;

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
typedef Protobuf::Message<TYPESTRING("SPU"), SPURam, SPUPorts, XAField, SPUIrq, SPUIrqPtr, Channels> SPU;
typedef Protobuf::MessageField<SPU, TYPESTRING("spu"), 7> SPUField;

typedef Protobuf::FieldValue<Protobuf::FixedBytes<0x1010>, TYPESTRING("buf"), 1> SIOBuf;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("stat_reg"), 2> SIOStatReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("mode_reg"), 3> SIOModeReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("ctrl_reg"), 4> SIOCtrlReg;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("baud_reg"), 5> SIOBaudReg;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("buf_count"), 6> SIOBufCount;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("parp"), 7> SIOParP;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("mcd_st"), 8> SIOMCDSt;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("rdwr"), 9> SIORDWR;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("adrh"), 10> SIOAdrH;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("adrl"), 11> SIOAdrL;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pad_st"), 12> SIOPadSt;
typedef Protobuf::Message<TYPESTRING("SIO"), SIOBuf, SIOStatReg, SIOModeReg, SIOCtrlReg, SIOBaudReg, SIOBufCount,
                          SIOParP, SIOMCDSt, SIORDWR, SIOAdrH, SIOAdrL, SIOPadSt>
    SIO;
typedef Protobuf::MessageField<SIO, TYPESTRING("sio"), 8> SIOField;

typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("ocup"), 1> CDOCUP;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("reg1_mode"), 2> CDReg1Mode;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("reg2"), 3> CDReg2;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("cmd_process"), 4> CDCmdProcess;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("ctrl"), 5> CDCtrl;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("stat"), 6> CDStat;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("stat_p"), 7> CDStatP;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<2352>, TYPESTRING("transfer"), 8> CDTransfer;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("transfer_index"), 9> CDTransferIndex;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<4>, TYPESTRING("prev"), 10> CDPrev;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<8>, TYPESTRING("param"), 11> CDParam;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<16>, TYPESTRING("result"), 12> CDResult;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("param_c"), 13> CDParamC;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("param_p"), 14> CDParamP;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("result_c"), 15> CDResultC;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("result_p"), 16> CDResultP;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("result_ready"), 17> CDResultReady;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("cmd"), 18> CDCmd;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("read"), 19> CDRead;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("set_loc_pending"), 20> CDSetLocPending;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("reading"), 21> CDReading;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<6>, TYPESTRING("result_tn"), 22> CDResultTN;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<4>, TYPESTRING("result_td"), 23> CDResultTD;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<4>, TYPESTRING("set_sector_play"), 24> CDSetSectorPlay;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<4>, TYPESTRING("set_sector_end"), 25> CDSetSectorEnd;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<4>, TYPESTRING("set_sector"), 26> CDSetSector;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("track"), 27> CDTrack;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("play"), 28> CDPlay;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("muted"), 29> CDMuted;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("cur_track"), 30> CDCurTrack;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("mode"), 31> CDMode;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("file"), 32> CDFile;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("channel"), 33> CDChannel;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("suceeded"), 34> CDSuceeded;
typedef Protobuf::FieldRef<Protobuf::Int32, TYPESTRING("first_sector"), 35> CDFirstSector;
typedef Protobuf::MessageField<XA, TYPESTRING("xa"), 36> CDXA;
typedef Protobuf::FieldRef<Protobuf::UInt16, TYPESTRING("irq"), 37> CDIRQ;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("irq_repeated"), 38> CDIrqRepeated;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("e_cycle"), 39> CDECycle;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("seeked"), 40> CDSeeked;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("read_scheduled"), 41> CDReadRescheduled;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("drive_state"), 42> CDDriveState;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("fast_forward"), 43> CDFastForward;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("fast_backward"), 44> CDFastBackward;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_left"), 45> CDAttenuatorLeftToLeft;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_right"), 46> CDAttenuatorLeftToRight;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_right"), 47> CDAttenuatorRightToRight;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_left"), 48> CDAttenuatorRightToLeft;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_left_t"), 49> CDAttenuatorLeftToLeftT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_left_to_right_t"), 50> CDAttenuatorLeftToRightT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_right_t"), 51> CDAttenuatorRightToRightT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("attenuator_right_to_left_t"), 52> CDAttenuatorRightToLeftT;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("subq_track"), 53> CDSubQTrack;
typedef Protobuf::FieldRef<Protobuf::UInt8, TYPESTRING("subq_index"), 54> CDSubQIndex;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<3>, TYPESTRING("subq_relative"), 55> CDSubQRelative;
typedef Protobuf::FieldValue<Protobuf::FixedBytes<3>, TYPESTRING("subq_absolute"), 56> CDSubQAbsolute;
typedef Protobuf::FieldRef<Protobuf::Bool, TYPESTRING("track_changed"), 57> CDTrackChanged;

typedef Protobuf::Message<
    TYPESTRING("CDRom"), CDOCUP, CDReg1Mode, CDReg2, CDCmdProcess, CDCtrl, CDStat, CDStatP, CDTransfer, CDTransferIndex,
    CDPrev, CDParam, CDResult, CDParamC, CDParamP, CDResultC, CDResultP, CDResultReady, CDCmd, CDRead, CDSetLocPending,
    CDReading, CDResultTN, CDResultTD, CDSetSectorPlay, CDSetSectorEnd, CDSetSector, CDTrack, CDPlay, CDMuted,
    CDCurTrack, CDMode, CDFile, CDChannel, CDSuceeded, CDFirstSector, CDXA, CDIRQ, CDIrqRepeated, CDECycle, CDSeeked,
    CDReadRescheduled, CDDriveState, CDFastForward, CDFastBackward, CDAttenuatorLeftToLeft, CDAttenuatorLeftToRight,
    CDAttenuatorRightToRight, CDAttenuatorRightToLeft, CDAttenuatorLeftToLeftT, CDAttenuatorLeftToRightT,
    CDAttenuatorRightToRightT, CDAttenuatorRightToLeftT, CDSubQTrack, CDSubQIndex, CDSubQRelative, CDSubQAbsolute,
    CDTrackChanged>
    CDRom;
typedef Protobuf::MessageField<CDRom, TYPESTRING("cdrom"), 9> CDRomField;

typedef Protobuf::Message<TYPESTRING("SaveState"), VersionString, Version, ThumbnailField, MemoryField, RegistersField,
                          GPUField, SPUField, SIOField, CDRomField>
    SaveState;

typedef Protobuf::ProtoFile<Thumbnail, Memory, IntCycles, Registers, GPU, ADPCMDecode, XA, ::PCSX::SPU::Chan::Data,
                            ::PCSX::SPU::ADSRInfo, ::PCSX::SPU::ADSRInfoEx, Channel, SPU, SIO, CDRom, SaveState>
    ProtoFile;

SaveState constructSaveState();

std::string save();
}  // namespace SaveStates

}  // namespace PCSX
