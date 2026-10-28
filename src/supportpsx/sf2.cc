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

#include "supportpsx/sf2.h"

#include <string.h>

#include <algorithm>

namespace {

// Generator operators, SoundFont 2.04 section 8.1.2.
constexpr uint16_t c_genInstrument = 41;
constexpr uint16_t c_genSampleID = 53;
constexpr uint16_t c_genSampleModes = 54;
// Zero points the specification requires after each sample.
constexpr uint32_t c_samplePad = 46;
// Points the specification requires between the loop end and the sample end.
constexpr uint32_t c_loopTail = 8;

class Buffer {
  public:
    void u8(uint8_t v) { m_data.push_back(v); }
    void u16(uint16_t v) {
        u8(v & 0xff);
        u8(v >> 8);
    }
    void u32(uint32_t v) {
        u16(v & 0xffff);
        u16(v >> 16);
    }
    void fourcc(const char* id) { bytes(id, 4); }
    void bytes(const void* data, size_t size) {
        auto p = reinterpret_cast<const uint8_t*>(data);
        m_data.insert(m_data.end(), p, p + size);
    }
    void name(const std::string& str) {
        char buf[20] = {};
        memcpy(buf, str.data(), std::min<size_t>(str.size(), 19));
        bytes(buf, 20);
    }
    void chunk(const char* id, const Buffer& body) {
        fourcc(id);
        u32(uint32_t(body.m_data.size()));
        bytes(body.m_data.data(), body.m_data.size());
        if (body.m_data.size() & 1) u8(0);
    }
    void list(const char* type, const Buffer& body) {
        fourcc("LIST");
        u32(uint32_t(body.m_data.size() + 4));
        fourcc(type);
        bytes(body.m_data.data(), body.m_data.size());
    }
    std::vector<uint8_t> m_data;
};

Buffer zstr(const std::string& str) {
    Buffer b;
    b.bytes(str.data(), str.size());
    b.u8(0);
    if (b.m_data.size() & 1) b.u8(0);
    return b;
}

Buffer infoList(const std::string& bankName, const std::string& comment) {
    Buffer info;
    Buffer ifil;
    ifil.u16(2);
    ifil.u16(1);
    info.chunk("ifil", ifil);
    info.chunk("isng", zstr("EMU8000"));
    info.chunk("INAM", zstr(bankName));
    if (!comment.empty()) info.chunk("ICMT", zstr(comment));
    info.chunk("ISFT", zstr("PCSX-Redux"));
    return info;
}

// Appends a sample's points to smpl and returns how many points past the end of its data were
// added. A loop running to the very end of the data gets the samples that follow its end when
// played, which are the first ones of the loop.
uint32_t appendPoints(Buffer& smpl, const PCSX::SF2::Sample& s) {
    for (auto v : s.pcm) smpl.u16(uint16_t(v));
    uint32_t tail = 0;
    if (s.loops && s.loopEnd > s.loopStart && s.loopEnd + c_loopTail > s.pcm.size()) {
        tail = s.loopEnd + c_loopTail - uint32_t(s.pcm.size());
        const uint32_t length = s.loopEnd - s.loopStart;
        const uint32_t phase = uint32_t(s.pcm.size()) - s.loopEnd;
        for (uint32_t k = 0; k < tail; k++) smpl.u16(uint16_t(s.pcm[s.loopStart + (phase + k) % length]));
    }
    for (uint32_t p = 0; p < c_samplePad; p++) smpl.u16(0);
    return tail;
}

void presetHeader(Buffer& phdr, const std::string& name, uint16_t preset, uint16_t bank, uint16_t bagIndex) {
    phdr.name(name);
    phdr.u16(preset);
    phdr.u16(bank);
    phdr.u16(bagIndex);
    phdr.u32(0);
    phdr.u32(0);
    phdr.u32(0);
}

void bag(Buffer& buffer, uint16_t genIndex) {
    buffer.u16(genIndex);
    buffer.u16(0);
}

// One preset, one instrument and one sample per input sample, all sharing its index.
class Hydra {
  public:
    void add(const PCSX::SF2::Sample& s, uint16_t i, uint32_t size) {
        presetHeader(phdr, s.name, i % 128, i / 128, i);
        bag(pbag, m_pgenCount);
        pgen.u16(c_genInstrument);
        pgen.u16(i);
        m_pgenCount++;

        inst.name(s.name);
        inst.u16(i);
        bag(ibag, m_igenCount);
        if (s.loops) {
            igen.u16(c_genSampleModes);
            igen.u16(1);
            m_igenCount++;
        }
        // sampleID has to be the last generator of an instrument zone.
        igen.u16(c_genSampleID);
        igen.u16(i);
        m_igenCount++;

        shdr.name(s.name);
        shdr.u32(m_offset);
        shdr.u32(m_offset + size);
        shdr.u32(m_offset + (s.loops ? s.loopStart : 0));
        shdr.u32(m_offset + (s.loops ? s.loopEnd : uint32_t(s.pcm.size())));
        shdr.u32(s.sampleRate);
        shdr.u8(s.rootKey);
        shdr.u8(0);
        shdr.u16(0);
        shdr.u16(1);  // mono
        m_offset += size + c_samplePad;
    }
    void terminate(uint16_t count) {
        presetHeader(phdr, "EOP", 0, 0, count);
        bag(pbag, m_pgenCount);
        for (unsigned i = 0; i < 10; i++) pmod.u8(0);
        pgen.u32(0);
        inst.name("EOI");
        inst.u16(count);
        bag(ibag, m_igenCount);
        for (unsigned i = 0; i < 10; i++) imod.u8(0);
        igen.u32(0);
        shdr.name("EOS");
        for (unsigned i = 0; i < 26; i++) shdr.u8(0);
    }
    Buffer list() const {
        Buffer pdta;
        pdta.chunk("phdr", phdr);
        pdta.chunk("pbag", pbag);
        pdta.chunk("pmod", pmod);
        pdta.chunk("pgen", pgen);
        pdta.chunk("inst", inst);
        pdta.chunk("ibag", ibag);
        pdta.chunk("imod", imod);
        pdta.chunk("igen", igen);
        pdta.chunk("shdr", shdr);
        return pdta;
    }

  private:
    Buffer phdr, pbag, pmod, pgen, inst, ibag, imod, igen, shdr;
    uint32_t m_offset = 0;
    uint16_t m_pgenCount = 0;
    uint16_t m_igenCount = 0;
};

}  // namespace

std::vector<uint8_t> PCSX::SF2::write(const std::vector<Sample>& samples, const std::string& bankName,
                                      const std::string& comment) {
    Buffer smpl;
    Hydra hydra;
    for (uint16_t i = 0; i < samples.size(); i++) {
        const uint32_t tail = appendPoints(smpl, samples[i]);
        hydra.add(samples[i], i, uint32_t(samples[i].pcm.size()) + tail);
    }
    hydra.terminate(uint16_t(samples.size()));

    Buffer sdta;
    sdta.chunk("smpl", smpl);

    Buffer body;
    body.fourcc("sfbk");
    body.list("INFO", infoList(bankName, comment));
    body.list("sdta", sdta);
    body.list("pdta", hydra.list());

    Buffer riff;
    riff.fourcc("RIFF");
    riff.u32(uint32_t(body.m_data.size()));
    riff.bytes(body.m_data.data(), body.m_data.size());
    return std::move(riff.m_data);
}
