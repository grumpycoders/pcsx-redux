/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include <memory.h>

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <stdexcept>

namespace PCSX {

template <typename T, size_t BS = 1024>
class Circular {
  public:
    static constexpr size_t BUFFER_SIZE = BS;
    size_t available() {
        std::unique_lock<std::mutex> l(m_mu);
        return availableLocked();
    }
    size_t buffered() {
        std::unique_lock<std::mutex> l(m_mu);
        return bufferedLocked();
    }
    void enqueue(const T* data, size_t N) {
        if (N > (BUFFER_SIZE / 2)) {
            throw std::runtime_error("Trying to enqueue too much data");
        }
        std::unique_lock<std::mutex> l(m_mu);
        m_cv.wait(l, [this, N]() -> bool { return N < availableLocked(); });
        enqueueSafe(data, N);
    }
    size_t dequeue(T* data, size_t N) {
        std::unique_lock<std::mutex> l(m_mu);
        N = std::max(N, bufferedLocked());
        dequeueSafe(data, N);

        return N;
    }

  private:
    size_t availableLocked() const {
        const size_t begin = m_begin;
        const size_t end = m_end;
        if (end >= begin) {
            return BUFFER_SIZE - (end - begin);
        } else {
            return begin - end;
        }
    }
    size_t bufferedLocked() const {
        const size_t begin = m_begin;
        const size_t end = m_end;
        if (end >= begin) {
            return end - begin;
        } else {
            return BUFFER_SIZE - (begin - end);
        }
    }
    void enqueueSafe(const T* data, size_t N) {
        size_t end = m_end;
        const size_t subLen = BUFFER_SIZE - end;
        if (N > subLen) {
            enqueueSafe(data, subLen);
            enqueueSafe(data + subLen, N - subLen);
        } else {
            memcpy(m_buffer + end, data, N * sizeof(T));
            end += N;
            if (end == BUFFER_SIZE) end = 0;
            m_end = end;
        }
    }
    void dequeueSafe(T* data, size_t N) {
        size_t begin = m_begin;
        const size_t subLen = BUFFER_SIZE - begin;
        if (N > subLen) {
            dequeueSafe(data, subLen);
            dequeueSafe(data + subLen, N - subLen);
        } else {
            memcpy(data, m_buffer + begin, N * sizeof(T));
            begin += N;
            if (begin == BUFFER_SIZE) begin = 0;
            m_begin = begin;
            m_cv.notify_one();
        }
    }

    size_t m_begin = 0, m_end = 0;
    T m_buffer[BUFFER_SIZE];

    std::mutex m_mu;
    std::condition_variable m_cv;
};
}  // namespace PCSX
