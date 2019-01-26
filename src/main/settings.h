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

#include <string>
#include <tuple>
#include <type_traits>

#include "json.hpp"
#include "typestring.hh"

namespace PCSX {

template <typename name>
class SettingString;
template <char... C>
class SettingString<irqus::typestring<C...>> {
  public:
    typedef irqus::typestring<C...> name;

  private:
    using myself = SettingString<name>;
    using type = std::string;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    void setDefault() { value = ""; }
    type value;
};

template <typename type, type defaultValue, typename name>
class Setting;
template <typename type, type defaultValue, char... C>
class Setting<type, defaultValue, irqus::typestring<C...>> {
  public:
    typedef irqus::typestring<C...> name;

  private:
    using myself = Setting<type, defaultValue, name>;

  public:
    operator type() const { return value; }
    myself &operator=(const type &v) {
        value = v;
        return *this;
    }
    void setDefault() { value = defaultValue; }
    type value = defaultValue;
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
    constexpr json serialize() const {
        json ret;
        serialize<0, settings...>(ret);
        return ret;
    }
    constexpr void deserialize(const json &j) { deserialize<0, settings...>(j); }

  private:
    template <size_t index>
    constexpr void reset() {}
    template <size_t index, typename settingType, typename... settings>
    constexpr void reset() {
        settingType &setting = std::get<index>(*this);
        setting.setDefault();
    }
    template <size_t index>
    constexpr void serialize(json &j) const {}
    template <size_t index, typename settingType, typename... settings>
    constexpr void serialize(json &j) const {
        const settingType &setting = std::get<index>(*this);
        j[settingType::name::data()] = setting.value;
        serialize<index + 1, settings...>(j);
    }
    template <size_t index>
    constexpr void deserialize(const json &j, bool setDefault = true) {}
    template <size_t index, typename settingType, typename... settings>
    constexpr void deserialize(const json &j, bool setDefault = true) {
        settingType &setting = std::get<index>(*this);
        try {
            if (j.find(settingType::name::data()) != j.end()) {
                setting.value = j[settingType::name::data()];
            } else if (setDefault) {
                setting.setDefault();
            }
        } catch (...) {
            if (setDefault) setting.setDefault();
        }
        deserialize<index + 1, settings...>(j);
    }
};

}  // namespace PCSX
