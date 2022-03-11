--lualoader, R"EOF(--
--OpenGL binding, taken and modified from https://github.com/malkia/luajit-opencl

ffi.cdef[[
typedef unsigned int GLenum;
typedef unsigned char GLboolean;
typedef unsigned int GLbitfield;
typedef signed char GLbyte;
typedef short GLshort;
typedef int GLint;
typedef int GLsizei;
typedef unsigned char GLubyte;
typedef unsigned short GLushort;
typedef unsigned int GLuint;
typedef float GLfloat;
typedef float GLclampf;
typedef double GLdouble;
typedef double GLclampd;
typedef void GLvoid;
typedef long GLintptr;
typedef long GLsizeiptr;
typedef char GLchar;
typedef char GLcharARB;
typedef void *GLhandleARB;
typedef long GLintptrARB;
typedef long GLsizeiptrARB;
typedef unsigned short GLhalfARB;
typedef unsigned short GLhalf;
]]

-- )EOF"
