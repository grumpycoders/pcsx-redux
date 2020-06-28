# Conversion of the official Sony libraries

Using the psyq-obj-parser tool, one can convert the Sony libraries into something usable for modern compilers. This is a bit of complex juggling act, as the original code was compiled with ccpsx, which is an utterly broken compiler. Making everything work fine between this old compiler and a newer gcc is a bit of a round hole square peg situation. Nonetheless, this sorts of works, and it has some advantages for further reverse engineering work.

## Extracting the old libraries

There is a tool in the old toolkit that can be used to extract all object files from a .LIB file: PSYLIBD. Alternatively, the other similar project called psyq2elf contains a dumper for these files: https://gitlab.com/jype/psyq2elf/-/blob/master/src/psyqdump.c

## Converting all the files

Simply compile and run the psyq-obj-parser tool:

```
$ psyq-obj-parser input.obj -o output.o
```

## Re-creating object files

The generated object files will be compatible to use by modern gcc, so you can simply use mipsel-linux-elf-ar to re-create .a files:

```
$ mipsel-linux-elf-ar rcs libsomething.a *.o
```

## Directory structure

This folder should contain a lib folder and an include folder. It ideally contains the following files:

```
include:
abs.h      gtereg.h    libcd.h    libhmd.h    libsnd.h  r3000.h   string.h
asm.h      gtereg_s.h  libcomb.h  libmath.h   libspu.h  rand.h    strings.h
assert.h   inline_a.h  libds.h    libmcrd.h   libtap.h  romio.h   sys/
convert.h  inline_c.h  libetc.h   libmcx.h    limits.h  setjmp.h
ctype.h    inline_o.h  libgpu.h   libpad.h    malloc.h  stdarg.h
fs.h       inline_s.h  libgs.h    libpress.h  mcgui.h   stddef.h
gtemac.h   kernel.h    libgte.h   libsio.h    memory.h  stdio.h
gtenom.h   libapi.h    libgun.h   libsn.h     qsort.h   stdlib.h

include/sys:
errno.h  fcntl.h  file.h  ioctl.h  types.h

lib:
libapi.a   libcomb.a  libgte.a   libmcx.a    libspu.a       poweron.obj.o
libc.a     libds.a    libgun.a   libpad.a    libtap.a
libc2.a    libetc.a   libhmd.a   libpress.a  mcgui.obj.o
libcard.a  libgpu.a   libmath.a  libsio.a    mcgui_e.obj.o
libcd.a    libgs.a    libmcrd.a  libsnd.a    noprint.obj.o
```

## Caveats of the conversion

The crt0 files (the files typically named 2MBYTE.OBJ, 8MBYTE.OBJ, NOHEAP.OBJ, and NONE3.OBJ) cannot be properly converted. The provided crt0 in the common folder should be providing an appropriate replacement however.
