/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <array>
#include <cassert>
#include <codecvt>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>

#include "core/system.h"
#include "json.hpp"
#include "lua/luawrapper.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/typestring-wrapper.h"
#include "typestring.hh"

namespace PCSX {

template <typename type, typename name, type defaultValue = type()>
struct Setting;
template <typename type, char... C, type defaultValue>
struct Setting<type, irqus::typestring<C...>, defaultValue> {
    using json = nlohmann::json;
    typedef irqus::typestring<C...> name;

    void pushLuaClosures(Lua L) {
        L.push(name::data());
        L.newtable();
        L.declareFunc(
            "index",
            [this](Lua L) -> int {
                if constexpr (std::is_same<type, bool>::value) {
                    L.push(value);
                } else if constexpr (std::is_enum<type>::value) {
                    L.push(magic_enum::enum_name(value));
                } else {
                    L.push(lua_Number(value));
                }
                return 1;
            },
            -1);
        L.declareFunc(
            "newindex",
            [this](Lua L) -> int {
                if constexpr (std::is_same<type, bool>::value) {
                    value = L.toboolean();
                } else if constexpr (std::is_enum<type>::value) {
                    auto v = magic_enum::enum_cast<type>(L.tostring());
                    if (v.has_value()) {
                        value = v.value();
                    }
                } else {
                    value = type(L.checknumber());
                }
                return 0;
            },
            -1);
        L.declareFunc(
            "reset",
            [this](Lua L) -> int {
                reset();
                return 0;
            },
            -1);
        L.settable();
    }

  private:
    using myself = Setting<type, name, defaultValue>;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    json serialize() const { return value; }
    void deserialize(const json &j) { value = j; }
    void reset() { value = defaultValue; }
    type value = defaultValue;
};

template <typename name, typename defaultValue = irqus::typestring<'\0'>>
struct SettingString;
template <char... C, char... D>
struct SettingString<irqus::typestring<C...>, irqus::typestring<D...>> {
    using json = nlohmann::json;
    typedef irqus::typestring<C...> name;
    typedef irqus::typestring<D...> defaultValue;
    typedef std::string type;

    void pushLuaClosures(Lua L) {
        L.push(name::data());
        L.newtable();
        L.declareFunc(
            "index",
            [this](Lua L) -> int {
                L.push(std::string_view(value.data(), value.size()));
                return 1;
            },
            -1);
        L.declareFunc(
            "newindex",
            [this](Lua L) -> int {
                value = L.tostring();
                return 0;
            },
            -1);
        L.declareFunc(
            "reset",
            [this](Lua L) -> int {
                reset();
                return 0;
            },
            -1);
        L.settable();
    }

  private:
    using myself = SettingString<name, defaultValue>;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    const char *c_str() const { return value.c_str(); }
    json serialize() const { return value; }
    void deserialize(const json &j) { value = j; }
    void reset() { value = defaultValue::data(); }
    type value = defaultValue::data();
};

template <typename name, typename defaultValue = irqus::typestring<'\0'>>
struct SettingPath;
template <char... C, char... D>
struct SettingPath<irqus::typestring<C...>, irqus::typestring<D...>> {
    using json = nlohmann::json;
    typedef irqus::typestring<C...> name;
    typedef irqus::typestring<D...> defaultValue;
    typedef std::filesystem::path type;

    void pushLuaClosures(Lua L) {
        L.push(name::data());
        L.newtable();
        L.declareFunc(
            "index",
            [this](Lua L) -> int {
                auto str = value.u8string();
                auto data = str.data();
                auto size = str.size();
                L.push(reinterpret_cast<char *>(data), size);
                return 1;
            },
            -1);
        L.declareFunc(
            "newindex",
            [this](Lua L) -> int {
                value = L.tostring();
                return 0;
            },
            -1);
        L.declareFunc(
            "reset",
            [this](Lua L) -> int {
                reset();
                return 0;
            },
            -1);
        L.settable();
    }

  private:
    using myself = SettingPath<name, defaultValue>;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    PCSX::u8string string() const { return value.u8string(); }
    bool empty() const { return value.u8string().empty(); }
    // C++20's u8strings will be the death of me.
    // Also, https://github.com/nlohmann/json/issues/1914
    json serialize() const { return reinterpret_cast<const char *>(value.u8string().c_str()); }
    void deserialize(const json &j) {
        std::string str = j;
        value = str;
    }
    void reset() { value = defaultValue::data(); }
    type value = defaultValue::data();
};

template <typename name, int defaultValue, int divisor>
struct SettingFloat;
template <char... C, int defaultValue, int divisor>
struct SettingFloat<irqus::typestring<C...>, defaultValue, divisor> {
    using json = nlohmann::json;
    static_assert(divisor != 0, "Can't have a SettingFloat with a divisor of 0");
    typedef irqus::typestring<C...> name;
    typedef float type;

    void pushLuaClosures(Lua L) {
        L.push(name::data());
        L.newtable();
        L.declareFunc(
            "index",
            [this](Lua L) -> int {
                L.push(value);
                return 1;
            },
            -1);
        L.declareFunc(
            "newindex",
            [this](Lua L) -> int {
                value = L.checknumber();
                return 0;
            },
            -1);
        L.declareFunc(
            "reset",
            [this](Lua L) -> int {
                reset();
                return 0;
            },
            -1);
        L.settable();
    }

  private:
    using myself = SettingFloat<name, defaultValue, divisor>;

  public:
    operator type() const { return value; }
    myself &operator=(const float &v) {
        value = v;
        return *this;
    }
    json serialize() const { return value; }
    void deserialize(const json &j) { value = j; }
    void reset() { value = (float)defaultValue / (float)divisor; }
    float value = (float)defaultValue / (float)divisor;
};

template <typename name, typename nestedSettings>
struct SettingNested;
template <char... C, typename nestedSettings>
struct SettingNested<irqus::typestring<C...>, nestedSettings> : public nestedSettings {
    typedef irqus::typestring<C...> name;

    void pushLuaClosures(Lua L) {
        L.push(name::data());
        L.newtable();
        L.push("value");
        nestedSettings::pushValue(L);
        L.settable();
        L.declareFunc(
            "index",
            [this](Lua L) -> int {
                L.getfield("value");
                return 1;
            },
            -1);
        L.declareFunc(
            "newindex", [this](Lua L) -> int { return 0; }, -1);
        L.declareFunc(
            "reset",
            [this](Lua L) -> int {
                nestedSettings::reset();
                return 0;
            },
            -1);
        L.settable();
    }
};

template <typename name, size_t N, typename nestedSetting>
struct SettingArray;
template <char... C, size_t N, typename nestedSetting>
struct SettingArray<irqus::typestring<C...>, N, nestedSetting> : public std::array<nestedSetting, N> {
    using json = nlohmann::json;
    typedef irqus::typestring<C...> name;
    json serialize() const {
        auto ret = json::array();
        for (auto &item : *this) {
            ret.push_back(item.serialize());
        }
        return ret;
    }
    void deserialize(const json &j) {
        int count = 0;
        for (auto &item : j) {
            nestedSetting s;
            s.deserialize(item);
            if (count < N) {
                (*this)[count] = s;
            }
            count++;
        }
        for (; count < N; count++) {
            (*this)[count].reset();
        }
    }
    void reset() {
        for (auto &item : *this) {
            item.reset();
        }
    }
};

template <typename... settings>
struct Settings : private std::tuple<settings...> {
    using json = nlohmann::json;
    template <typename setting>
    constexpr const setting &get() const {
        return std::get<setting>(*this);
    }
    template <typename setting>
    constexpr setting &get() {
        return std::get<setting>(*this);
    }
    constexpr void reset() { reset<0, settings...>(); }
    json serialize() const {
        json ret;
        serialize<0, settings...>(ret);
        return ret;
    }
    constexpr void deserialize(const json &j) { deserialize<0, settings...>(j); }
    void pushValue(Lua L) {
        L.newtable();
        L.newtable();
        L.push("keys");
        L.newtable();
        pushValue<0, settings...>(L);
        L.settable();
        L.declareFunc("__index", lua_index, -1);
        L.declareFunc("__newindex", lua_newindex, -1);
        L.declareFunc("__pairs", lua_pairswrapper, -1);
        L.setmetatable();
    }
    static int lua_index(lua_State *L_) {
        Lua L(L_);
        int r = L.getmetatable(-2);
        if (r != 1) return 0;
        L.getfield("keys");
        L.remove(-2);
        L.copy(-2);
        L.gettable();
        if (!L.istable()) return 0;
        L.getfield("index");
        if (!L.isfunction()) return 0;
        L.copy(-2);
        L.pcall(1);
        return 1;
    }
    static int lua_newindex(lua_State *L_) {
        Lua L(L_);
        int r = L.getmetatable(-3);
        if (r != 1) return 0;
        L.getfield("keys");
        L.copy(-4);
        L.gettable();
        if (!L.istable()) return 0;
        L.getfield("newindex");
        if (!L.isfunction()) return 0;
        L.copy(-5);
        L.pcall(1);
        return 0;
    }
    static int lua_pairswrapper(lua_State *L_) {
        Lua L(L_);
        int r = L.getmetatable();
        if (r != 1) return 0;
        L.push([](lua_State *L_) {
            Lua L(L_);
            int r = L.next();
            if (r == 0) return 0;
            L.getfield("index");
            L.copy(-2);
            L.pcall(1);
            L.remove(-2);
            return 2;
        });
        L.getfield("keys", -2);
        L.push();
        return 3;
    }

  private:
    template <size_t index>
    constexpr void reset() {}
    template <size_t index, typename settingType, typename... nestedSettings>
    constexpr void reset() {
        settingType &setting = std::get<index>(*this);
        setting.reset();
        reset<index + 1, nestedSettings...>();
    }
    template <size_t index>
    constexpr void serialize(json &j) const {}
    template <size_t index, typename settingType, typename... nestedSettings>
    constexpr void serialize(json &j) const {
        const settingType &setting = std::get<index>(*this);
        j[settingType::name::data()] = setting.serialize();
        serialize<index + 1, nestedSettings...>(j);
    }
    template <size_t index>
    constexpr void deserialize(const json &j, bool doReset = true) {}
    template <size_t index, typename settingType, typename... nestedSettings>
    constexpr void deserialize(const json &j, bool doReset = true) {
        settingType &setting = std::get<index>(*this);
        try {
            if (j.find(settingType::name::data()) != j.end()) {
                setting.deserialize(j[settingType::name::data()]);
            } else if (doReset) {
                setting.reset();
            }
        } catch (...) {
            if (doReset) setting.reset();
        }
        deserialize<index + 1, nestedSettings...>(j, doReset);
    }
    template <size_t index>
    void pushValue(Lua L) {}
    template <size_t index, typename settingType, typename... nestedSettings>
    void pushValue(Lua L) {
        settingType &setting = std::get<index>(*this);
        setting.pushLuaClosures(L);
        pushValue<index + 1, nestedSettings...>(L);
    }
};

}  // namespace PCSX
