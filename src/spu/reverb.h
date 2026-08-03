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

    // Neill/Pete reverb mixing buffer (allocated/freed by the impl, which stores
    // the pointers here).
    int *sRVBPlay = 0;
    int *sRVBEnd = 0;
    int *sRVBStart = 0;

    // Fake-reverb preset timing, set by setPreset() from the reverb-mode register.
    int iReverbOff = -1;
    int iReverbRepeat = 0;
    int iReverbNum = 1;

    // Zero the reverb work state (was memset(&rvb, 0, sizeof(REVERBInfo))).
    void reset();

    // Reverb-mode register write (was impl::SetREVERB).
    void setPreset(uint16_t val);
    // Per-voice reverb arm on key-on (was impl::StartREVERB). mode = reverb setting.
    void start(SPUCHAN *voice, uint16_t spuCtrl, int mode);
    // Re-init the Neill mixing buffer each block (was impl::InitREVERB).
    void init(int mode, int nssize);
    // Mix one active reverb voice into the buffer (was impl::StoreREVERB).
    void store(SPUCHAN *voice, int ns, int mode);
    // Produce the left/right wet-out sample (was impl::MixREVERBLeft / MixREVERBRight).
    int mixLeft(int ns, uint16_t *spuMem, uint16_t spuCtrl, int mode);
    int mixRight(int mode);

  private:
    // Reverb work-area access helpers (was impl::g_buffer / s_buffer / s_buffer1);
    // spuMem is the SPU sound RAM base.
    int g_buffer(int iOff, uint16_t *spuMem);
    void s_buffer(int iOff, int iVal, uint16_t *spuMem);
    void s_buffer1(int iOff, int iVal, uint16_t *spuMem);
};

}  // namespace SPU

}  // namespace PCSX
