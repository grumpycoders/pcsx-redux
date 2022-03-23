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

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <limits>
#include <string>
#include <variant>

#include "fmt/format.h"

namespace PCSX {

class Slice {
  public:
    Slice() {}
    template <size_t L>
    Slice(const char (&data)[L]) {
        borrow(data, L - 1);
    }
    Slice(const Slice &other) { copyFrom(other); }
    Slice(Slice &&other) noexcept { moveFrom(std::move(other)); }
    Slice(const std::string &str) { m_data = str; }
    Slice(std::string &&str) { m_data = std::move(str); }
    std::string asString() const {
        if (std::holds_alternative<std::string>(m_data)) {
            return std::get<std::string>(m_data);
        }
        return {static_cast<const char *>(data()), size()};
    }
    Slice &operator=(const Slice &other) {
        copyFrom(other);
        return *this;
    }
    Slice &operator=(Slice &&other) noexcept {
        moveFrom(std::move(other));
        return *this;
    }
    Slice &operator+=(const Slice &other) {
        concatenate(other);
        return *this;
    }
    void concatenate(const Slice &other) {
        auto newSize = size() + other.size();
        if (std::holds_alternative<Owned>(m_data)) {
            auto &data = std::get<Owned>(m_data);
            data.ptr = realloc(data.ptr, newSize);
            memcpy(((uint8_t *)data.ptr) + size(), other.data(), other.size());
            data.size += other.size();
        } else if (std::holds_alternative<std::string>(m_data)) {
            auto &data = std::get<std::string>(m_data);
            auto oldSize = data.size();
            data.resize(newSize);
            memcpy(((uint8_t *)data.data()) + oldSize, other.data(), other.size());
        } else {
            uint8_t *newData = (uint8_t *)malloc(newSize);
            memcpy(newData, data(), size());
            memcpy(newData + size(), other.data(), other.size());
            acquire(newData, newSize);
        }
    }
    void copy(const Slice &other) {
        if (std::holds_alternative<std::string>(other.m_data)) {
            m_data = other.m_data;
        } else {
            copy(other.data(), other.size());
        }
    }
    void copy(const std::string &str) { m_data = str; }
    void copy(const void *data, uint32_t size) {
        void *dest;
        if (size <= INLINED_SIZE) {
            m_data = Inlined{size};
            dest = std::get<Inlined>(m_data).inlined;
        } else {
            m_data = Owned{size, malloc(size)};
            dest = std::get<Owned>(m_data).ptr;
        }
        memcpy(dest, data, size);
    }
    void acquire(std::string &&str) { m_data = std::move(str); }
    void acquire(void *data, uint32_t size) {
        m_data = Owned{size, malloc(size)};
        std::get<Owned>(m_data).ptr = data;
        std::get<Owned>(m_data).size = size;
    }
    void borrow(const Slice &other, uint32_t from = 0, uint32_t amount = std::numeric_limits<uint32_t>::max()) {
        const uint8_t *ptr = static_cast<const uint8_t *>(other.data());
        uint32_t size = other.size();
        if (from >= size) {
            m_data = std::monostate();
            return;
        }
        ptr += from;
        size -= from;
        borrow(ptr, std::min(amount, size));
    }
    template <size_t L>
    void borrow(const char (&data)[L]) {
        m_data = Borrowed{L - 1, data};
    }
    void borrow(const void *data, uint32_t size) { m_data = Borrowed{size, data}; }
    const void *data() const {
        if (std::holds_alternative<std::string>(m_data)) {
            return std::get<std::string>(m_data).data();
        } else if (std::holds_alternative<Inlined>(m_data)) {
            return std::get<Inlined>(m_data).inlined;
        } else if (std::holds_alternative<Owned>(m_data)) {
            return std::get<Owned>(m_data).ptr;
        } else if (std::holds_alternative<Borrowed>(m_data)) {
            return std::get<Borrowed>(m_data).ptr;
        }
        return nullptr;
    }
    const uint32_t size() const {
        if (std::holds_alternative<std::string>(m_data)) {
            return std::get<std::string>(m_data).size();
        } else if (std::holds_alternative<Inlined>(m_data)) {
            return std::get<Inlined>(m_data).size;
        } else if (std::holds_alternative<Owned>(m_data)) {
            return std::get<Owned>(m_data).size;
        } else if (std::holds_alternative<Borrowed>(m_data)) {
            return std::get<Borrowed>(m_data).size;
        }
        return 0;
    }
    std::string toHexString() const {
        const uint8_t *buf = (const uint8_t *)data();
        std::string ret;
        for (unsigned lineOffset = 0; lineOffset < size(); lineOffset += 16) {
            ret += fmt::format("{:06x}: ", lineOffset);
            for (unsigned offset = 0; offset < 16; offset++) {
                if (lineOffset + offset < size()) {
                    ret += fmt::format("{:02x} ", buf[lineOffset + offset]);
                } else {
                    ret += "   ";
                }
            }
            ret += " ";
            for (unsigned offset = 0; offset < 16; offset++) {
                if (lineOffset + offset < size()) {
                    ret += fmt::format("{}", isprint(buf[lineOffset + offset]) ? (char)buf[lineOffset + offset] : '.');
                }
            }
            ret += "\n";
        }
        return ret;
    }

    uint8_t getByte(size_t offset) {
        if (offset >= size()) throw std::runtime_error("getByte called with an out of range offset");
        return reinterpret_cast<const uint8_t *>(data())[offset];
    }

  private:
    void copyFrom(const Slice &other) {
        if (std::holds_alternative<Owned>(other.m_data)) {
            copy(other.data(), other.size());
        } else {
            m_data = other.m_data;
        }
    }
    void moveFrom(Slice &&other) {
        m_data = std::move(other.m_data);
        if (std::holds_alternative<Owned>(other.m_data)) {
            std::get<Owned>(other.m_data).ptr = nullptr;
        }
        other.m_data = std::monostate();
    }
    static constexpr size_t INLINED_SIZE = 28;
    struct Inlined {
        uint32_t size;
        uint8_t inlined[INLINED_SIZE];
    };
    struct Owned {
        ~Owned() { free(ptr); }
        uint32_t size;
        void *ptr;
    };
    struct Borrowed {
        uint32_t size;
        const void *ptr;
    };
    std::variant<std::monostate, std::string, Inlined, Owned, Borrowed> m_data;
};

}  // namespace PCSX
