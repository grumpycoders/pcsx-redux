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

#pragma once

#include <stdint.h>

#include "spu/types.h"

namespace PCSX {

namespace SPU {

// The SPU's single global reverb unit. Holds the register-mapped reverb work
// state (REVERBInfo), the reverb mixing buffer pointers, and the Pete/Neill
// reverb DSP. Extracted out of the SPU impl; the arithmetic is unchanged - the
// method bodies are the former impl::*REVERB* members moved verbatim, with the
// formerly-implicit impl state (the reverb mode setting, SPUCTRL, sound RAM,
// NSSIZE) now passed in as parameters so the unit owns only reverb state.
//
// Like the noise generator this is a single per-SPU instance and lives in the
// impl rather than in SPUCHAN. The `rvb`, `sRVB*` and `iReverb*` members keep
// their original names so the moved bodies reference them unchanged.
class ReverbUnit {
  public:
    // SPUCTRL bit 7: reverb master enable (was impl::ControlFlags::ReverbMasterEnable).
    static constexpr uint16_t kReverbMasterEnable = 1 << 7;

    // Reverb work state, written directly by the register handlers.
    REVERBInfo rvb;

    // Reverb mixing buffer (allocated/freed by the impl, which stores the pointer
    // here). One interleaved stereo pair per sample of the batch.
    int *mixStart = 0;

    // Zero the reverb work state (was memset(&rvb, 0, sizeof(REVERBInfo))).
    void reset();

    // Per-voice reverb arm on key-on (was impl::StartREVERB).
    void start(SPUCHAN *voice, uint16_t spuCtrl);
    // Re-init the mixing buffer each block (was impl::InitREVERB).
    void init(int nssize);
    // Mix one active reverb voice into the buffer (was impl::StoreREVERB).
    void store(SPUCHAN *voice, int ns);
    // Produce the left/right wet-out sample (was impl::MixREVERBLeft / MixREVERBRight).
    int mixLeft(int ns, uint16_t *spuMem, uint16_t spuCtrl);
    int mixRight();

  private:
    // The reverb work area is a circular window in sound RAM. Offsets are counted
    // in 32-bit units from CurrAddr, wrap at the top of RAM back to StartAddr, and
    // are the one piece of arithmetic every work-area access shares. ExtraSample is
    // the half-sample stagger the IIR destinations write at; it is a template
    // parameter because it is only ever 0 or 1 and it selects the whole access.
    int wrapOffset(int offset, int extraSample) const;
    int getBuffer(int offset, uint16_t *spuMem) const;
    template <int ExtraSample>
    void setBuffer(int offset, int value, uint16_t *spuMem);

};

}  // namespace SPU

}  // namespace PCSX
