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

#include <stddef.h>
#include <stdint.h>

#include <codecvt>
#include <filesystem>
#include <string>
#include <tuple>
#include <type_traits>

#include "json.hpp"
#include "typestring.hh"

namespace PCSX {

template <typename type, typename name, type defaultValue = type()>
class Setting;
template <typename type, char... C, type defaultValue>
class Setting<type, irqus::typestring<C...>, defaultValue> {
    using json = nlohmann::json;

  public:
    typedef irqus::typestring<C...> name;

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
    void setDefault() { value = defaultValue; }
    type value = defaultValue;
};

template <typename name, typename defaultValue = irqus::typestring<'\0'>>
class SettingString;
template <char... C, char... D>
class SettingString<irqus::typestring<C...>, irqus::typestring<D...>> {
    using json = nlohmann::json;

  public:
    typedef irqus::typestring<C...> name;
    typedef irqus::typestring<D...> defaultValue;
    typedef std::string type;

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
    void setDefault() { value = defaultValue::data(); }
    type value = defaultValue::data();
};

template <typename name, typename defaultValue = irqus::typestring<'\0'>>
class SettingPath;
template <char... C, char... D>
class SettingPath<irqus::typestring<C...>, irqus::typestring<D...>> {
    using json = nlohmann::json;

  public:
    typedef irqus::typestring<C...> name;
    typedef irqus::typestring<D...> defaultValue;
    typedef std::filesystem::path type;

  private:
    using myself = SettingPath<name, defaultValue>;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    std::string string() const { return value.u8string(); }
    bool empty() const { return value.u8string().empty(); }
    json serialize() const { return value.u8string(); }
    void deserialize(const json &j) {
        std::string str = j;
        value = std::filesystem::u8path(str);
    }
    void setDefault() { value = defaultValue::data(); }
    type value = defaultValue::data();
};

template <typename... settings>
class Settings : private std::tuple<settings...> {
    using json = nlohmann::json;

  public:
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

  private:
    template <size_t index>
    constexpr void reset() {}
    template <size_t index, typename settingType, typename... nestedSettings>
    constexpr void reset() {
        settingType &setting = std::get<index>(*this);
        setting.setDefault();
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
    constexpr void deserialize(const json &j, bool setDefault = true) {}
    template <size_t index, typename settingType, typename... nestedSettings>
    constexpr void deserialize(const json &j, bool setDefault = true) {
        settingType &setting = std::get<index>(*this);
        try {
            if (j.find(settingType::name::data()) != j.end()) {
                setting.deserialize(j[settingType::name::data()]);
            } else if (setDefault) {
                setting.setDefault();
            }
        } catch (...) {
            if (setDefault) setting.setDefault();
        }
        deserialize<index + 1, nestedSettings...>(j);
    }
};

}  // namespace PCSX

#ifdef _MSC_VER
#define TYPESTRING_MAX_CONST_CHAR 99

#define TYPESTRING_MIN(a, b) (a) < (b) ? (a) : (b)

#define TYPESTRING(s)                                                                                               \
    irqus::typestring<                                                                                              \
        ts_getChr(s, 0), ts_getChr(s, 1), ts_getChr(s, 2), ts_getChr(s, 3), ts_getChr(s, 4), ts_getChr(s, 5),       \
        ts_getChr(s, 6), ts_getChr(s, 7), ts_getChr(s, 8), ts_getChr(s, 9), ts_getChr(s, 10), ts_getChr(s, 11),     \
        ts_getChr(s, 12), ts_getChr(s, 13), ts_getChr(s, 14), ts_getChr(s, 15), ts_getChr(s, 16), ts_getChr(s, 17), \
        ts_getChr(s, 18), ts_getChr(s, 19), ts_getChr(s, 20), ts_getChr(s, 21), ts_getChr(s, 22), ts_getChr(s, 23), \
        ts_getChr(s, 24), ts_getChr(s, 25), ts_getChr(s, 26), ts_getChr(s, 27), ts_getChr(s, 28), ts_getChr(s, 29), \
        ts_getChr(s, 30), ts_getChr(s, 31), ts_getChr(s, 32), ts_getChr(s, 33), ts_getChr(s, 34), ts_getChr(s, 35), \
        ts_getChr(s, 36), ts_getChr(s, 37), ts_getChr(s, 38), ts_getChr(s, 39), ts_getChr(s, 40), ts_getChr(s, 41), \
        ts_getChr(s, 42), ts_getChr(s, 43), ts_getChr(s, 44), ts_getChr(s, 45), ts_getChr(s, 46), ts_getChr(s, 47), \
        ts_getChr(s, 48), ts_getChr(s, 49), ts_getChr(s, 50), ts_getChr(s, 51), ts_getChr(s, 52), ts_getChr(s, 53), \
        ts_getChr(s, 54), ts_getChr(s, 55), ts_getChr(s, 56), ts_getChr(s, 57), ts_getChr(s, 58), ts_getChr(s, 59), \
        ts_getChr(s, 60), ts_getChr(s, 61), ts_getChr(s, 62), ts_getChr(s, 63), ts_getChr(s, 64), ts_getChr(s, 65), \
        ts_getChr(s, 66), ts_getChr(s, 67), ts_getChr(s, 68), ts_getChr(s, 69), ts_getChr(s, 70), ts_getChr(s, 71), \
        ts_getChr(s, 72), ts_getChr(s, 72), ts_getChr(s, 72), ts_getChr(s, 73), ts_getChr(s, 74), ts_getChr(s, 75), \
        ts_getChr(s, 76), ts_getChr(s, 77), ts_getChr(s, 78), ts_getChr(s, 79), ts_getChr(s, 80), ts_getChr(s, 81), \
        ts_getChr(s, 82), ts_getChr(s, 83), ts_getChr(s, 84), ts_getChr(s, 85), ts_getChr(s, 86), ts_getChr(s, 87), \
        ts_getChr(s, 88), ts_getChr(s, 89), ts_getChr(s, 90), ts_getChr(s, 91), ts_getChr(s, 92), ts_getChr(s, 93), \
        ts_getChr(s, 94), ts_getChr(s, 95), ts_getChr(s, 96), ts_getChr(s, 97), ts_getChr(s, 98), ts_getChr(s, 99)>

#define ts_getChr(name, ii) \
    ((TYPESTRING_MIN(ii, TYPESTRING_MAX_CONST_CHAR)) < sizeof(name) / sizeof(*name) ? name[ii] : 0)

#else
#define TYPESTRING(s) typestring_is(s)
#endif
