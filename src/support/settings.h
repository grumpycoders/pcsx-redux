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

#include <cassert>
#include <codecvt>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <tuple>
#include <type_traits>

#include "core/system.h"
#include "json.hpp"
#include "support/typestring-wrapper.h"
#include "typestring.hh"

namespace PCSX {

template <typename type, typename name, type defaultValue = type()>
struct Setting;
template <typename type, char... C, type defaultValue>
struct Setting<type, irqus::typestring<C...>, defaultValue> {
    using json = nlohmann::json;
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
};

template <typename name, typename nestedSetting>
struct SettingArray;
template <char... C, typename nestedSetting>
struct SettingArray<irqus::typestring<C...>, nestedSetting> : public std::vector<nestedSetting> {
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
        for (auto &item : j) {
            nestedSetting s;
            s.deserialize(item);
            this->push_back(s);
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
};

}  // namespace PCSX
