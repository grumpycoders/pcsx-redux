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
#include <gl/gl3w.h>

#include <functional>
#include <initializer_list>
#include <iostream>
#include <string_view>

namespace PCSX {
namespace OpenGL {

#define MAKE_WRAPPER(Object)                             \
    struct Object {                                      \
        GLuint m_handle = 0;                             \
                                                         \
        void create() {                                  \
            if (m_handle == 0) {                         \
                glGen##Object##s(1, &m_handle);          \
            }                                            \
        }                                                \
        Object(bool shouldCreate = false) {              \
            if (shouldCreate) {                          \
                create();                                \
            }                                            \
        }                                                \
                                                         \
        ~Object() { glDelete##Object##s(1, &m_handle); } \
        GLuint handle() { return m_handle; }             \
        bool exists() { return m_handle != 0; }          \
    };

MAKE_WRAPPER(Buffer);
MAKE_WRAPPER(Framebuffer);
MAKE_WRAPPER(Texture);
MAKE_WRAPPER(VertexArray);
MAKE_WRAPPER(Sampler);
#undef MAKE_WRAPPER

struct Shader {
    GLuint m_handle = 0;

    // Returns whether compilation failed or not
    bool create(const std::string_view source, GLenum type) {
        m_handle = glCreateShader(type);
        const GLchar* const sources[1] = {source.data()};

        glShaderSource(m_handle, 1, sources, nullptr);
        glCompileShader(m_handle);

        GLint success;
        glGetShaderiv(m_handle, GL_COMPILE_STATUS, &success);
        if (success == GL_FALSE) {
            char buf[4096];
            glGetShaderInfoLog(m_handle, 4096, nullptr, buf);
            fprintf(stderr, "Failed to compile shader\nError: %s\n", buf);
            glDeleteShader(m_handle);

            m_handle = 0;
        }

        return m_handle != 0;
    }

    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
};

struct Program {
    GLuint m_handle = 0;

    bool create(std::initializer_list<std::reference_wrapper<Shader>> shaders) {
        m_handle = glCreateProgram();
        for (const auto& shader : shaders) {
            glAttachShader(m_handle, shader.get().handle());
        }

        glLinkProgram(m_handle);
        GLint success;
        glGetShaderiv(m_handle, GL_LINK_STATUS, &success);

        if (success == GL_FALSE) {
            char buf[4096];
            glGetProgramInfoLog(m_handle, 4096, nullptr, buf);
            fprintf(stderr, "Failed to link program\nError: %s\n", buf);
            glDeleteProgram(m_handle);

            m_handle = 0;
        }

        return m_handle != 0;
    }

    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
};

}  // end namespace OpenGL
}  // end namespace PCSX
