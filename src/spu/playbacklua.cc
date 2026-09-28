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

#include <stdint.h>

#include <algorithm>
#include <cstring>
#include <exception>
#include <memory>
#include <string>

#include "lua/luawrapper.h"
#include "spu/sdlaudio.h"

namespace {

PCSX::SPU::SDLAudio* s_audio = nullptr;

// Must match the LuaSoundDescriptor declaration in playbackffi.lua.
struct LuaSoundDescriptor {
    int32_t format;
    uint32_t bits;
    int32_t isSigned;
    uint32_t channels;
    uint32_t rate;
    int32_t sectors;
    int32_t xaFile;
    int32_t xaChannel;
    float gain;
};

struct LuaSound {
    std::shared_ptr<PCSX::SPU::SDLAudio::Sound> sound;
};

void setError(char* errorBuffer, uint32_t errorSize, const std::string& error) {
    if (!errorBuffer || (errorSize == 0)) return;
    size_t len = std::min<size_t>(error.size(), errorSize - 1);
    memcpy(errorBuffer, error.data(), len);
    errorBuffer[len] = 0;
}

LuaSound* spuPlayAudio(const uint8_t* data, uint64_t size, const LuaSoundDescriptor* desc, char* errorBuffer,
                       uint32_t errorSize) {
    using Descriptor = PCSX::SPU::SDLAudio::SoundDescriptor;
    if (!s_audio) {
        setError(errorBuffer, errorSize, "audio output isn't initialized");
        return nullptr;
    }
    Descriptor descriptor;
    switch (desc->format) {
        case 0:
            descriptor.format = Descriptor::Format::PCM;
            break;
        case 1:
            descriptor.format = Descriptor::Format::SPU;
            break;
        case 2:
            descriptor.format = Descriptor::Format::XA;
            break;
        default:
            setError(errorBuffer, errorSize, "unknown audio format");
            return nullptr;
    }
    descriptor.bits = desc->bits;
    descriptor.isSigned = desc->isSigned != 0;
    descriptor.channels = desc->channels;
    descriptor.rate = desc->rate;
    descriptor.sectors = desc->sectors != 0;
    descriptor.xaFile = desc->xaFile;
    descriptor.xaChannel = desc->xaChannel;
    descriptor.gain = desc->gain;
    // Exceptions can't cross the ffi boundary.
    try {
        std::string error;
        auto sound = s_audio->playSound(data, size, descriptor, error);
        if (!sound) {
            setError(errorBuffer, errorSize, error);
            return nullptr;
        }
        return new LuaSound{std::move(sound)};
    } catch (std::exception& e) {
        setError(errorBuffer, errorSize, e.what());
        return nullptr;
    }
}

void spuDestroySound(LuaSound* sound) { delete sound; }
void spuStopSound(LuaSound* sound) { sound->sound->stop(); }
bool spuSoundIsPlaying(LuaSound* sound) { return sound->sound->isPlaying(); }
void spuSetSoundGain(LuaSound* sound, float gain) { sound->sound->setGain(gain); }

template <typename T, size_t S>
void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("SPU_PLAYBACK");
    L.newtable();
    REGISTER(L, spuPlayAudio);
    REGISTER(L, spuDestroySound);
    REGISTER(L, spuStopSound);
    REGISTER(L, spuSoundIsPlaying);
    REGISTER(L, spuSetSoundGain);
    L.settable();
    L.pop();
}

}  // namespace

void PCSX::SPU::SDLAudio::setLua(Lua L) {
    static int lualoader = 1;
    static const char* playbackFFI = (
#include "spu/playbackffi.lua"
    );
    s_audio = this;
    registerAllSymbols(L);
    L.load(playbackFFI, "src:spu/playbackffi.lua");
}
