/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "supportpsx/ps1-packer.h"

#include <stdint.h>

#include <exception>
#include <vector>

#include "mips/common/util/encoder.hh"
#include "n2e-d.h"
#include "ucl/ucl.h"

using namespace Mips::Encoder;
constexpr uint64_t PSEXE = 0x45584520582d5350;

namespace {

template <typename T>
void pushBytes(std::vector<uint8_t>& data, T value) {
    for (unsigned i = 0; i < sizeof(T); i++) {
        data.push_back(value & 0xff);
        value >>= 8;
    }
}

int16_t getHI(uint32_t v) {
    int16_t lo = v & 0xffff;
    int16_t hi = v >> 16;
    return lo < 0 ? hi + 1 : hi;
}

int16_t getLO(uint32_t v) {
    int16_t ret = v & 0xffff;
    return ret;
}

}  // namespace

void PCSX::PS1Packer::pack(IO<File> src, IO<File> dest, uint32_t addr, uint32_t pc, uint32_t gp, uint32_t sp,
                           const Options& options) {
    std::vector<uint8_t> dataIn;
    dataIn.resize(src->size());
    src->read(dataIn.data(), dataIn.size());
    while ((dataIn.size() & 3) != 0) dataIn.push_back(0);

    std::vector<uint8_t> dataOut;
    dataOut.resize(dataIn.size() * 1.2 + 2064);
    ucl_uint outSize;
    int r;

    r = ucl_nrv2e_99_compress(dataIn.data(), dataIn.size(), dataOut.data() + (options.raw ? 16 : 0), &outSize, nullptr,
                              10, nullptr, nullptr);
    if (r != UCL_E_OK) {
        throw std::runtime_error("Fatal error during data compression.\n");
    }
    dataOut.resize(outSize + (options.raw ? 16 : 0));
    uint32_t newPC;
    uint32_t compLoad;
    bool inplace;

    while ((dataOut.size() & 3) != 0) {
        dataOut.push_back(0);
    }
    uint32_t tload = options.rom ? 0x1f000110 : options.tload;

    if (tload != 0) {
        compLoad = tload;
        newPC = compLoad + dataOut.size();
        inplace = false;
    } else {
        newPC = addr + dataIn.size() + 16;
        compLoad = newPC - dataOut.size();
        inplace = true;
    }
    newPC += sizeof(n2e_d::code);

    if (options.raw) {
        std::vector<uint8_t> stub;
        pushBytes(stub, lui(Reg::V0, getHI(newPC)));
        pushBytes(stub, addiu(Reg::V0, Reg::V0, getLO(newPC)));
        pushBytes(stub, jr(Reg::V0));
        pushBytes<uint32_t>(stub, 0);
        std::copy(stub.begin(), stub.end(), dataOut.begin());
        compLoad += stub.size();
    }

    for (auto b : n2e_d::code) pushBytes<uint32_t>(dataOut, b);

    pushBytes(dataOut, addiu(Reg::T8, Reg::RA, 0));
    pushBytes(dataOut, lui(Reg::V1, 0x1f80));
    pushBytes(dataOut, sw(Reg::R0, 0x1074, Reg::V1));
    pushBytes(dataOut, lui(Reg::A0, getHI(compLoad)));
    pushBytes(dataOut, addiu(Reg::A0, Reg::A0, getLO(compLoad)));
    pushBytes(dataOut, lui(Reg::A1, getHI(addr)));
    pushBytes(dataOut, bgezal(Reg::R0, -((int16_t)(sizeof(n2e_d::code) + 7 * 4))));
    pushBytes(dataOut, addiu(Reg::A1, Reg::A1, getLO(addr)));
    if (options.shell) {
        pushBytes(dataOut, bgezal(Reg::R0, 36));
        pushBytes(dataOut, addiu(Reg::S0, Reg::R0, 0xa0));
        // this goes to 0x40
        pushBytes(dataOut, mtc0(Reg::R0, 7));
        pushBytes(dataOut, jr(Reg::RA));
        pushBytes(dataOut, rfe());
        // this goes to 0x80030000
        pushBytes(dataOut, lui(Reg::T0, getHI(pc)));
        pushBytes(dataOut, addiu(Reg::T0, Reg::T0, getLO(pc)));
        pushBytes(dataOut, lui(Reg::GP, getHI(gp)));
        pushBytes(dataOut, jr(Reg::T0));
        pushBytes(dataOut, addiu(Reg::GP, Reg::GP, getLO(gp)));
        // copying stuff around
        pushBytes(dataOut, addiu(Reg::S1, Reg::RA, 0));

        pushBytes(dataOut, addiu(Reg::A0, Reg::R0, 0x40));
        pushBytes(dataOut, addiu(Reg::A1, Reg::S1, 0));
        pushBytes(dataOut, addiu(Reg::A2, Reg::R0, 12));
        pushBytes(dataOut, jalr(Reg::S0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x2a));

        pushBytes(dataOut, lui(Reg::A0, 0x8003));
        pushBytes(dataOut, addiu(Reg::A1, Reg::S1, 12));
        pushBytes(dataOut, addiu(Reg::A2, Reg::R0, 20));
        pushBytes(dataOut, jalr(Reg::S0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x2a));

        constexpr uint32_t partialReboot = 0xbfc00390;

        pushBytes(dataOut, lui(Reg::RA, getHI(partialReboot)));
        pushBytes(dataOut, addiu(Reg::RA, Reg::RA, getLO(partialReboot)));

        pushBytes(dataOut, lui(Reg::T0, 0b1100101010000000));
        pushBytes(dataOut, lui(Reg::T1, 0x8003));
        pushBytes(dataOut, addiu(Reg::T2, Reg::R0, -1));
        pushBytes(dataOut, mtc0(Reg::R0, 7));
        pushBytes(dataOut, mtc0(Reg::T1, 5));
        pushBytes(dataOut, mtc0(Reg::T2, 9));
        pushBytes(dataOut, mtc0(Reg::T0, 7));

        pushBytes(dataOut, jr(Reg::S0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x44));
    } else {
        pushBytes(dataOut, addiu(Reg::T0, Reg::R0, 0xa0));
        pushBytes(dataOut, jalr(Reg::T0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x44));
        pushBytes(dataOut, lui(Reg::T0, getHI(pc)));
        pushBytes(dataOut, addiu(Reg::T0, Reg::T0, getLO(pc)));
        pushBytes(dataOut, jr(Reg::T0));
        pushBytes(dataOut, addiu(Reg::RA, Reg::T8, 0));
    }
    while (!options.cpe && !options.booty && !options.rom && !options.raw && ((dataOut.size() & 0x7ff) != 0)) {
        dataOut.push_back(0);
    }

    std::vector<uint8_t> header;
    if (options.booty || options.rom) {
        std::vector<uint32_t> stage2;
        if (options.booty) {
            /* 0x24 */ stage2.push_back(lw(Reg::A3, 0, Reg::A1));
            /* 0x28 */ stage2.push_back(addiu(Reg::A2, Reg::A2, -1));
            /* 0x2c */ stage2.push_back(sw(Reg::A3, 0, Reg::A0));
            /* 0x30 */ stage2.push_back(bne(Reg::A2, Reg::R0, -16));
            /* 0x34 */ stage2.push_back(addiu(Reg::A0, Reg::A0, 4));
            /* 0x38 */ stage2.push_back(j(0xa0));
            /* 0x3c */ stage2.push_back(addiu(Reg::T1, Reg::R0, 0x44));
            /* 0x40 */ stage2.push_back(mtc0(Reg::R0, 7));
            /* 0x44 */ stage2.push_back(lui(Reg::A0, compLoad >> 16));
            if ((compLoad & 0xffff) != 0) {
                /* 0x48 */ stage2.push_back(ori(Reg::A0, Reg::A0, compLoad));
            }
            /* 0x4c */ stage2.push_back(lui(Reg::RA, newPC >> 16));
            if ((newPC & 0xffff) != 0) {
                /* 0x50 */ stage2.push_back(ori(Reg::RA, Reg::RA, newPC));
            }
            /* 0x54 */ stage2.push_back(lui(Reg::A1, 0xbf00));
            /* 0x58 */ stage2.push_back(j(0x24));
            /* 0x5c */ stage2.push_back(ori(Reg::A2, Reg::R0, dataOut.size() / 4));
        } else {
            stage2.push_back(lui(Reg::V0, newPC >> 16));
            if ((newPC & 0xffff) != 0) {
                stage2.push_back(ori(Reg::V0, Reg::V0, newPC & 0xffff));
            }
            stage2.push_back(jr(Reg::V0));
            stage2.push_back(mtc0(Reg::R0, 7));
            static constexpr char disclaimer[] =
                "This is self-decompressing binary,"
                " suitable for a flash cart rom, "
                "created by ps1-packer (https://bit.ly/pcsx-redux). "
                "It is NOT";
            for (auto b : disclaimer) {
                header.push_back(b);
            }
            while (header.size() < 0x80) {
                header.push_back(0);
            }
            pushBytes<uint32_t>(header, 0x1f0000b4);
        }

        static constexpr uint8_t license[] = {
            0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x53, 0x6f, 0x6e, 0x79,
            0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x74,
            0x61, 0x69, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x00, 0x00, 0x00, 0x1f,
        };

        for (auto b : license) {
            pushBytes(header, b);
        }

        // break on writes and/or exec
        pushBytes(header, mtc0(Reg::R0, 7));
        pushBytes(header, addiu(Reg::T2, Reg::R0, 0xffff));
        pushBytes(header, lui(Reg::T1, 0x8003));
        pushBytes(header, lui(Reg::T0, 0xeb80));
        pushBytes(header, mtc0(Reg::T2, 11));
        pushBytes(header, mtc0(Reg::T2, 9));
        pushBytes(header, mtc0(Reg::T1, 5));
        pushBytes(header, mtc0(Reg::T1, 3));
        pushBytes(header, mtc0(Reg::T0, 7));

        int16_t base = options.booty ? 0x24 : 0x40;
        uint32_t last = 0;
        for (auto b : stage2) {
            if (b == 0) {
                last = sw(Reg::R0, base, Reg::R0);
            } else {
                pushBytes(header, lui(Reg::T0, b >> 16));
                uint16_t rest = b;
                if (rest != 0) {
                    pushBytes(header, ori(Reg::T0, Reg::T0, rest));
                }
                last = sw(Reg::T0, base, Reg::R0);
            }
            pushBytes(header, last);
            base += 4;
        }
        header.pop_back();
        header.pop_back();
        header.pop_back();
        header.pop_back();
        pushBytes(header, jr(Reg::RA));
        pushBytes(header, last);
        if (options.rom) {
            while (header.size() < (tload & 0xffffff)) {
                header.push_back(0);
            }
        }
    } else if (options.cpe) {
        pushBytes<uint32_t>(header, 0x1455043);
        pushBytes<uint16_t>(header, 0x0008);
        pushBytes<uint8_t>(header, 3);
        pushBytes<uint16_t>(header, 0x0090);
        pushBytes<uint32_t>(header, newPC);
        pushBytes<uint8_t>(header, 1);
        pushBytes<uint32_t>(header, compLoad);
        pushBytes<uint32_t>(header, dataOut.size());
        dataOut.push_back(0);
    } else if (!options.raw) {
        pushBytes(header, PSEXE);
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes(header, newPC);
        pushBytes(header, gp);
        pushBytes(header, compLoad);
        pushBytes(header, dataOut.size());
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes(header, sp);
        while (header.size() < 0x800) {
            header.push_back(0);
        }
    }

    dest->write(header.data(), header.size());
    dest->write(dataOut.data(), dataOut.size());
}
