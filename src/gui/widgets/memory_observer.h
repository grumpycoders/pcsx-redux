/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <array>
#include <vector>

#include "imgui.h"
#include "immintrin.h"

namespace PCSX {

namespace Widgets {

class MemoryObserver {
  public:
    void draw(const char* title);
    bool m_show = false;

  private:
    static int getMemValue(uint32_t absoluteAddress, const uint8_t* memData, uint32_t memSize, uint32_t memBase,
                           uint8_t stride);

    /**
     * Delta-over-time search.
     */

    enum class ScanType {
        ExactValue,
        BiggerThan,
        SmallerThan,
        Changed,
        Unchanged,
        Increased,
        Decreased,
        UnknownInitialValue
    };

    enum class ScanAlignment : uint8_t { OneByte = 1, TwoBytes = 2, FourBytes = 4 };

    struct AddressValuePair {
        uint32_t address = 0;
        int scannedValue = 0;
    };

    ScanType m_scanType = ScanType::ExactValue;
    ScanAlignment m_scanAlignment = ScanAlignment::OneByte;
    std::vector<AddressValuePair> m_addressValuePairs;
    bool m_hex = false;
    int m_value = 0;

    /**
     * Pattern search.
     */

    template <int bufferSize>
    static __m256i avx2_getShuffleResultsFor(const std::array<uint8_t, bufferSize>& buffer,
                                             std::array<uint8_t, 32>& extendedBuffer, int mask) {
        static_assert(bufferSize == 8 || bufferSize == 16);

        for (auto j = 0u; j < (32 / bufferSize); ++j) {
            std::ranges::copy(buffer, extendedBuffer.begin() + j * bufferSize);
        }
        const auto twoCopies = _mm256_loadu_epi8(extendedBuffer.data());

        switch (mask) {
            case 0: {
                const auto firstShuffleMask = _mm256_set_epi8(3, 2, 1, 0, 7, 6, 5, 4, 2, 1, 0, 7, 6, 5, 4, 3, 1, 0, 7,
                                                              6, 5, 4, 3, 2, 0, 7, 6, 5, 4, 3, 2, 1);
                const auto firstShuffle = _mm256_shuffle_epi8(twoCopies, firstShuffleMask);
                return _mm256_cmpeq_epi8(twoCopies, firstShuffle);
            }
            case 1: {
                const auto secondShuffleMask = _mm256_set_epi8(7, 6, 5, 4, 3, 2, 1, 0, 6, 5, 4, 3, 2, 1, 0, 7, 5, 4, 3,
                                                               2, 1, 0, 7, 6, 4, 3, 2, 1, 0, 7, 6, 5);
                const auto secondShuffle = _mm256_shuffle_epi8(twoCopies, secondShuffleMask);
                return _mm256_cmpeq_epi8(twoCopies, secondShuffle);
            }
            case 2: {
                assert(bufferSize == 16);
                const auto thirdShuffleMask = _mm256_set_epi8(11, 10, 9, 8, 7, 6, 5, 4, 10, 9, 8, 7, 6, 5, 4, 3, 9, 8,
                                                              7, 6, 5, 4, 3, 2, 8, 7, 6, 5, 4, 3, 2, 1);
                const auto thirdShuffle = _mm256_shuffle_epi8(twoCopies, thirdShuffleMask);
                return _mm256_cmpeq_epi8(twoCopies, thirdShuffle);
            }
            case 3: {
                assert(bufferSize == 16);
                const auto fourthShuffleMask =
                    _mm256_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 14, 13, 12, 11, 10, 9, 8, 7, 13, 12, 11, 10, 9, 8, 7,
                                    6, 12, 11, 10, 9, 8, 7, 6, 5);
                const auto fourthShuffle = _mm256_shuffle_epi8(twoCopies, fourthShuffleMask);
                return _mm256_cmpeq_epi8(twoCopies, fourthShuffle);
            }
            default:
                return _mm256_setzero_si256();
        }
    }

    template <int bufferSize>
    void avx2_populateAddressList(const uint8_t* memData, uint32_t memBase, uint32_t memSize) {
        static_assert(bufferSize == 8 || bufferSize == 16);

        alignas(32) auto buffer = std::array<uint8_t, bufferSize>{};
        alignas(32) auto extendedBuffer = std::array<uint8_t, 32>{};

        const auto sequenceSize = m_sequenceSize;
        std::copy_n(m_sequence, sequenceSize, buffer.data());
        auto patternShuffleResults = std::vector<__m256i>{avx2_getShuffleResultsFor(buffer, extendedBuffer, 0),
                                                          avx2_getShuffleResultsFor(buffer, extendedBuffer, 1)};
        if constexpr (bufferSize == 16) {
            patternShuffleResults.push_back(avx2_getShuffleResultsFor(buffer, extendedBuffer, 2));
            patternShuffleResults.push_back(avx2_getShuffleResultsFor(buffer, extendedBuffer, 3));
        }

        m_addresses.clear();
        const auto step = m_step;
        for (auto i = 0u; i + sequenceSize < memSize; i += step) {
            std::copy_n(memData + i, sequenceSize, buffer.data());

            bool bAllEqual = true;
            for (auto j = 0u; j < patternShuffleResults.size(); ++j) {
                bAllEqual = all_equal(
                    _mm256_cmpeq_epi8(patternShuffleResults[j], avx2_getShuffleResultsFor(buffer, extendedBuffer, j)));
                if (!bAllEqual) {
                    break;
                }
            }

            if (bAllEqual) {
                m_addresses.push_back(memBase + i);
            }
        }
    }

    static bool all_equal(__m256i input);
    static std::vector<uint8_t> getShuffleResultsFor(const std::vector<uint8_t>& buffer);
    static bool matchesPattern(const std::vector<uint8_t>& buffer, const std::vector<uint8_t>& patternShuffleResults);
    void populateAddressList(const uint8_t* memData, uint32_t memBase, uint32_t memSize);

    int m_sequenceSize = 255;
    char m_sequence[256]{};
    int m_step = 1;
    std::vector<uint32_t> m_addresses;
};

}  // namespace Widgets

}  // namespace PCSX
