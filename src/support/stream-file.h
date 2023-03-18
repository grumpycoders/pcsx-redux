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
    using pos_type = typename std::basic_streambuf<CharType, traits>::pos_type;

  public:
    BasicFileStreamBuf(IO<File> file) : m_file(file) {}

  private:
    virtual pos_type seekpos(pos_type sp, std::ios_base::openmode which) {
        return seekoff(sp, std::ios_base::beg, which);
    }
    virtual pos_type seekoff(std::streamoff off, std::ios_base::seekdir way, std::ios_base::openmode which) {
        int wheel = 0;
        switch (way) {
            case std::ios_base::beg:
                wheel = SEEK_SET;
                break;
            case std::ios_base::cur:
                wheel = SEEK_CUR;
                break;
            case std::ios_base::end:
                wheel = SEEK_END;
                break;
        }
        if (which & std::ios_base::out) {
            m_file->wSeek(off, wheel);
        }
        if (which & std::ios_base::in) {
            this->setg(m_buffer, m_buffer, m_buffer);
            m_file->rSeek(off, wheel);
        }
        return m_file->rTell();
    }
    virtual typename traits::int_type underflow() {
        if (this->gptr() == this->egptr()) {
            auto amountRead = m_file->read(m_buffer, sizeof(m_buffer));
            this->setg(m_buffer, m_buffer, m_buffer + amountRead);
        }
        return this->gptr() == this->egptr() ? std::char_traits<char>::eof()
                                             : std::char_traits<char>::to_int_type(*this->gptr());
    }
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
    char m_buffer[1024];
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

template <class CharType, class traits = std::char_traits<CharType> >
class BasicFileIStream : public std::basic_istream<CharType, traits> {
  public:
    BasicFileIStream(IO<File> file)
        : std::basic_ios<CharType, traits>(&m_sbuf), std::basic_istream<CharType, traits>(&m_sbuf), m_sbuf(file) {}

  private:
    BasicFileStreamBuf<CharType, traits> m_sbuf;
};

typedef BasicFileIStream<char> FileIStream;

}  // namespace PCSX
