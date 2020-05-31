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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <variant>

namespace PCSX {
class Slice {
  public:
    Slice() {}
    Slice(const Slice &other) { copy(other.data(), other.size()); }
    Slice(Slice &&other) {
        m_data = other.m_data;
        other.m_data = std::monostate();
    }
    Slice(const std::string &str) { m_data = str; }
    Slice(std::string &&str) { m_data = std::move(str); }
    ~Slice() { maybeFree(); }
    std::string toString() const { return {static_cast<const char *>(data()), size()}; }
    Slice &operator=(const Slice &other) { copy(other.data(), other.size()); }
    Slice &operator=(Slice &&other) {
        m_data = other.m_data;
        other.m_data = std::monostate();
        return *this;
    }
    void copy(const std::string &str) { m_data = str; }
    void copy(const void *data, uint32_t size) {
        maybeFree();
        void *dest;
        if (size < INLINED_SIZE) {
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
        maybeFree();
        m_data = Owned{size, malloc(size)};
        std::get<Owned>(m_data).ptr = data;
        std::get<Owned>(m_data).size = size;
    }
    void borrow(const void *data, uint32_t size) {
        maybeFree();
        m_data = Borrowed{size, data};
    }
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

  private:
    void maybeFree() {
        if (!std::holds_alternative<Owned>(m_data)) return;
        free(std::get<Owned>(m_data).ptr);
        m_data = std::monostate();
    }
    static constexpr size_t INLINED_SIZE = 28;
    struct Inlined {
        uint32_t size;
        uint8_t inlined[INLINED_SIZE];
    };
    struct Owned {
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
