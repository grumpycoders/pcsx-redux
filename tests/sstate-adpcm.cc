/*
 * A voice parked at AdpcmDecoder::kStopped must come back stopped from a save
 * state, whatever address sound RAM happens to live at.
 */

#include <stdint.h>

#include "gtest/gtest.h"
#include "spu/adpcm.h"

namespace {

using PCSX::SPU::AdpcmDecoder;

// saveTo and loadFrom only do pointer arithmetic against the base, so it never
// needs to point at real memory. Pick one above 4 GiB, like a 64-bit heap. Its
// low 32 bits must not be zero: an old state then stored kStopped as -1, which
// can't be told apart from a null cursor.
uint8_t *const kHighBase = reinterpret_cast<uint8_t *>(uintptr_t(0x78351234a000ull));

struct Fields {
    PCSX::Protobuf::Int32 h1, h2, start, curr, loop, pos;
    PCSX::Protobuf::Int32 sb[AdpcmDecoder::kSamplesPerBlock];
};

void save(const AdpcmDecoder &d, Fields &f, uint8_t *base) {
    d.saveTo(f.h1, f.h2, f.start, f.curr, f.loop, base, f.sb, f.pos);
}

void load(AdpcmDecoder &d, const Fields &f, uint8_t *base) {
    d.loadFrom(f.h1, f.h2, f.start, f.curr, f.loop, base, f.sb, f.pos);
}

}  // namespace

TEST(SaveStateAdpcm, StoppedCursorRoundTrips) {
    AdpcmDecoder saved;
    saved.setStart(kHighBase + 0x1000);
    saved.setCurr(AdpcmDecoder::kStopped);
    saved.setLoop(nullptr);
    Fields f;
    save(saved, f, kHighBase);

    AdpcmDecoder loaded;
    load(loaded, f, kHighBase);
    EXPECT_TRUE(loaded.stopped());
    EXPECT_EQ(loaded.start(), kHighBase + 0x1000);
    EXPECT_EQ(loaded.loop(), nullptr);
}

TEST(SaveStateAdpcm, ValidCursorRoundTrips) {
    AdpcmDecoder saved;
    saved.setCurr(kHighBase + AdpcmDecoder::kRamSize - 16);
    Fields f;
    save(saved, f, kHighBase);

    AdpcmDecoder loaded;
    load(loaded, f, kHighBase);
    EXPECT_FALSE(loaded.stopped());
    EXPECT_EQ(loaded.curr(), kHighBase + AdpcmDecoder::kRamSize - 16);
}

// States written before kStoppedOffset stored kStopped as a truncated pointer
// difference. Those must load as stopped, not as a wild pointer.
TEST(SaveStateAdpcm, LegacyStoppedCursorLoadsStopped) {
    Fields f;
    AdpcmDecoder blank;
    save(blank, f, kHighBase);
    f.curr.value = int32_t(uint32_t(uintptr_t(AdpcmDecoder::kStopped) - uintptr_t(kHighBase)));

    AdpcmDecoder loaded;
    load(loaded, f, kHighBase);
    EXPECT_TRUE(loaded.stopped());
}
