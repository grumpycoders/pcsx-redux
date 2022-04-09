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

#include <cassert>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <string_view>
#include <type_traits>

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

    void setAttribute(GLuint index, GLint size, GLenum type, bool normalized, GLsizei stride, const void* offset) {
        glVertexAttribPointer(index, size, type, normalized, stride, offset);
    }

    void setAttribute(GLuint index, GLint size, GLenum type, bool normalized, GLsizei stride, size_t offset) {
        glVertexAttribPointer(index, size, type, normalized, stride, reinterpret_cast<const void*>(offset));
    }

    void enableAttribute(GLuint index) { glEnableVertexAttribArray(index); }
    void disableAttribute(GLuint index) { glDisableVertexAttribArray(index); }
};

enum FramebufferTypes {
    DrawFramebuffer = GL_DRAW_FRAMEBUFFER,
    ReadFramebuffer = GL_READ_FRAMEBUFFER,
    DrawAndReadFramebuffer = GL_FRAMEBUFFER
};

struct Texture {
    GLuint m_handle = 0;
    int m_width, m_height;

    void create(int width, int height, GLint internalFormat) {
        m_width = width;
        m_height = height;

        glGenTextures(1, &m_handle);
        bind();
        glTexStorage2D(GL_TEXTURE_2D, 1, internalFormat, width, height);
    }

    ~Texture() { glDeleteTextures(1, &m_handle); }
    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
    void bind() { glBindTexture(GL_TEXTURE_2D, m_handle); }
    int width() { return m_width; }
    int height() { return m_height; }
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

    void createWithTexture(Texture& tex, GLenum mode = GL_FRAMEBUFFER) {
        create();
        bind(mode);
        glFramebufferTexture2D(mode, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex.handle(), 0);
    }

    void createWithReadTexture(Texture& tex) { createWithTexture(tex, GL_READ_FRAMEBUFFER); }
    void createWithDrawTexture(Texture& tex) { createWithTexture(tex, GL_DRAW_FRAMEBUFFER); }
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

struct VertexBuffer {
    GLuint m_handle = 0;

    void create() {
        if (m_handle == 0) {
            glGenBuffers(1, &m_handle);
        }
    }
    VertexBuffer(bool shouldCreate = false) {
        if (shouldCreate) {
            create();
        }
    }

    ~VertexBuffer() { glDeleteBuffers(1, &m_handle); }
    GLuint handle() { return m_handle; }
    bool exists() { return m_handle != 0; }
    void bind() { glBindBuffer(GL_ARRAY_BUFFER, m_handle); }

    template <typename VertType>
    void bufferVerts(VertType* vertices, int vertCount, GLenum usage = GL_DYNAMIC_DRAW) {
        glBufferData(GL_ARRAY_BUFFER, sizeof(VertType) * vertCount, vertices, usage);
    }
};

static void setClearColor(float val) { glClearColor(val, val, val, val); }
static void setClearColor(float r, float g, float b, float a) { glClearColor(r, g, b, a); }
static void setClearDepth(float depth) { glClearDepthf(depth); }
static void clearColor() { glClear(GL_COLOR_BUFFER_BIT); }
static void clearDepth() { glClear(GL_DEPTH_BUFFER_BIT); }
static void clearColorAndDepth() { glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT); }

static void setViewport(GLsizei width, GLsizei height) { glViewport(0, 0, width, height); }
static void setViewport(GLsizei x, GLsizei y, GLsizei width, GLsizei height) { glViewport(x, y, width, height); }
static void setScissor(GLsizei width, GLsizei height) { glScissor(0, 0, width, height); }
static void setScissor(GLsizei x, GLsizei y, GLsizei width, GLsizei height) { glScissor(x, y, width, height); }

static void bindScreenFramebuffer() { glBindFramebuffer(GL_FRAMEBUFFER, 0); }
static void enableScissor() { glEnable(GL_SCISSOR_TEST); }
static void disableScissor() { glDisable(GL_SCISSOR_TEST); }
static void enableBlend() { glEnable(GL_BLEND); }
static void disableBlend() { glDisable(GL_BLEND); }

enum Primitives {
    Triangle = GL_TRIANGLES,
    Triangles = Triangle,
    Tri = Triangle,
    Tris = Triangle,
    TriangleStrip = GL_TRIANGLE_STRIP,
    TriangleFan = GL_TRIANGLE_FAN,
    Line = GL_LINES,
    Lines = Line,
    LineStrip = GL_LINE_STRIP,
    Point = GL_POINTS,
    Points = Point
};

static void draw(Primitives prim, GLsizei vertexCount) { glDrawArrays(static_cast<GLenum>(prim), 0, vertexCount); }
static void draw(Primitives prim, GLint first, GLsizei vertexCount) {
    glDrawArrays(static_cast<GLenum>(prim), first, vertexCount);
}

enum FillMode {
    DrawPoints = GL_POINT,
    DrawWire = GL_LINE,
    FillPoly = GL_FILL
};

static void setFillMode(GLenum mode) { glPolygonMode(GL_FRONT_AND_BACK, mode); }
static void setFillMode(FillMode mode) { glPolygonMode(GL_FRONT_AND_BACK, static_cast<GLenum>(mode)); }
static void drawWireframe() { setFillMode(DrawWire); }

template <typename T>
T get(GLenum query) {
    T ret{};
    if constexpr (std::is_same<T, GLint>()) {
        glGetIntegerv(query, &ret);
    } else if constexpr (std::is_same<T, GLfloat>()) {
        glGetFloatv(query, &ret);
    } else if constexpr (std::is_same<T, GLdouble>()) {
        glGetDoublev(query, &ret);
    } else if constexpr (std::is_same<T, GLboolean>()) {
        glGetBooleanv(query, &ret);
    } else {
        static_assert(0, "Invalid type for OpenGL::get");
    }

    return ret;
}

static GLint getDrawFramebuffer() { return get<GLint>(GL_DRAW_FRAMEBUFFER_BINDING); }
static GLint getTex2D() { return get<GLint>(GL_TEXTURE_BINDING_2D); }

}  // end namespace OpenGL
}  // end namespace PCSX
