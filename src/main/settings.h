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
    const char *c_str() const { return value.string().c_str(); }
    json serialize() const { return value.string(); }
    void deserialize(const json &j) {
        std::string str = j;
        value = std::filesystem::path(str);
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
