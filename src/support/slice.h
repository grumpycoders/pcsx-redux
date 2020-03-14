/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <utility>

namespace PCSX {

class Slice {
  public:
    Slice() : m_isInlined(false), m_isOwned(false), m_size(0) { m_data.ptr = nullptr; }
    Slice(const Slice &other) { copyFrom(other); }
    Slice(Slice &&other) { moveFrom(std::move(other)); }
    ~Slice() { maybeFree(); }
    Slice &operator=(const Slice &other) {
        maybeFree();
        copyFrom(other);
    }
    Slice &operator=(Slice &&other) {
        maybeFree();
        moveFrom(std::move(other));
    }
    void copy(const void *data, uint32_t size) {
        assert(size < (1 << 30));
        maybeFree();
        m_size = size;
        m_isOwned = true;
        if (size > sizeof(m_data.inlined)) {
            m_isInlined = false;
            m_data.ptr = (uint8_t *)malloc(size);
            assert(m_data.ptr);
            memcpy(m_data.ptr, data, size);
        } else {
            m_isInlined = true;
            memcpy(m_data.inlined, data, size);
        }
    }
    void acquire(void *data, uint32_t size) {
        assert(size < (1 << 30));
        maybeFree();
        m_size = size;
        m_isOwned = true;
        m_isInlined = false;
        m_data.ptr = data;
    }
    void borrow(const void *data, uint32_t size) {
        assert(size < (1 << 30));
        maybeFree();
        m_size = size;
        m_isOwned = false;
        m_isInlined = false;
        m_data.ptr = const_cast<void *>(data);
    }
    const void *data() const { return m_isInlined ? m_data.inlined : m_data.ptr; }
    const uint32_t size() const { return m_size; }

  private:
    void maybeFree() {
        if (m_isOwned && !m_isInlined) free(m_data.ptr);
        m_isOwned = m_isInlined = false;
    }
    void copyFrom(const Slice &other) {
        if (other.m_isOwned) {
            copy(other.data(), other.size());
        } else {
            m_isOwned = false;
            m_isInlined = false;
            m_size = other.m_size;
            m_data.ptr = other.m_data.ptr;
        }
    }
    void moveFrom(Slice &&other) {
        m_data = other.m_data;
        m_isInlined = other.m_isInlined;
        m_isOwned = other.m_isOwned;
        m_size = other.m_size;

        other.m_isInlined = false;
        other.m_isOwned = false;
        other.m_size = 0;
    }
    union {
        uint8_t inlined[24];
        void *ptr;
    } m_data;
    bool m_isInlined : 1;
    bool m_isOwned : 1;
    uint32_t m_size : 30;
};

}  // namespace PCSX
