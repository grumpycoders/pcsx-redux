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

#include <cstring>
#include <istream>
#include <ostream>
#include <streambuf>

#include "support/file.h"

namespace PCSX {

template <class CharType, class traits = std::char_traits<CharType> >
class BasicFileStreamBuf : public std::basic_streambuf<CharType, traits> {
  public:
    BasicFileStreamBuf(IO<File> file) : m_file(file) {}

  private:
    virtual typename traits::int_type overflow(typename traits::int_type c) override {
        if (traits::eq_int_type(c, traits::eof())) return traits::not_eof(c);

        CharType ch = c;
        if (m_file->write(&ch, sizeof(ch)) != sizeof(ch)) return traits::eof();
        return traits::not_eof(c);
    }
    virtual std::streamsize xsputn(const CharType* s, std::streamsize count) override {
        return m_file->write(s, count);
    }

  public:
    IO<File> m_file;
};

template <class CharType, class traits = std::char_traits<CharType> >
class BasicFileOStream : public std::basic_ostream<CharType, traits> {
  public:
    BasicFileOStream(IO<File> file)
        : std::basic_ios<CharType, traits>(&m_sbuf), std::basic_ostream<CharType, traits>(&m_sbuf), m_sbuf(file) {}

  private:
    BasicFileStreamBuf<CharType, traits> m_sbuf;
};

typedef BasicFileOStream<char> FileOStream;

}  // namespace PCSX
