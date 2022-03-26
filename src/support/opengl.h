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

struct VertexArray {
    GLuint m_handle = 0;

    void create() {
        if (m_handle == 0) {
            glGenVertexArrays(1, &m_handle);
        }
    }
    VertexArray(bool shouldCreate = false) {
        if (shouldCreate) {
            create();
        }
    }

    ~VertexArray() { glDeleteVertexArrays(1, &m_handle); }
    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
    void bind() { glBindVertexArray(m_handle); }
};

enum FramebufferTypes {
    DrawFramebuffer = GL_DRAW_FRAMEBUFFER,
    ReadFramebuffer = GL_READ_FRAMEBUFFER,
    DrawAndReadFramebuffer = GL_FRAMEBUFFER
};

struct Framebuffer {
    GLuint m_handle = 0;

    void create() {
        if (m_handle == 0) {
            glGenFramebuffers(1, &m_handle);
        }
    }
    Framebuffer(bool shouldCreate = false) {
        if (shouldCreate) {
            create();
        }
    }

    ~Framebuffer() { glDeleteFramebuffers(1, &m_handle); }
    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
    void bind(GLenum target) { glBindFramebuffer(target, m_handle); }
    void bind(FramebufferTypes target) { bind(static_cast<GLenum>(target)); }
};

struct Texture {
    GLuint m_handle = 0;
    int m_width, m_height;

    void create(int width, int height, GLint internalFormat, GLenum format, GLenum type, const void* data = nullptr) {
        m_width = width;
        m_height = height;

        glGenTextures(1, &m_handle);
        bind();
        glTexImage2D(GL_TEXTURE_2D, 0, internalFormat, width, height, 0, format, type, data);
    }

    ~Texture() { glDeleteTextures(1, &m_handle); }
    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
    void bind() { glBindTexture(GL_TEXTURE_2D, m_handle); }
    int width() { return m_width; }
    int height() { return m_height; }
};

enum ShaderType {
    Fragment = GL_FRAGMENT_SHADER,
    Vertex = GL_VERTEX_SHADER,
    Geometry = GL_GEOMETRY_SHADER,
    Compute = GL_COMPUTE_SHADER,
    TessControl = GL_TESS_CONTROL_SHADER,
    TessEvaluation = GL_TESS_EVALUATION_SHADER
};

struct Shader {
    GLuint m_handle = 0;

    Shader() {}
    Shader(const std::string_view source, ShaderType type) { create(source, static_cast<GLenum>(type)); }

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
    void use() { glUseProgram(m_handle); }
};

}  // end namespace OpenGL
}  // end namespace PCSX
