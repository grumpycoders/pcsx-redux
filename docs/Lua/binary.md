# Handling of PSX binaries

There is some support for handling PSX binaries in the Lua API. The `PCSX.Binary` module has the following functions:

- `PCSX.Binary.load(input, output)`: loads an input `File` object into an output `File` object. The input file must be a valid PSX binary, which can be in the formats CPE, PS-EXE, PSF, or ELF, and the output file must be at least 4GB large, which means it's really only suitable with the `mem4g` object, or the object returned by `getMemoryAsFile()`. The output file will be modified in-place. The output file will be loaded at the address specified in the binary header. If successful, the function will return an info structure with the following optional fields:
    - `pc`: the entry point of the binary
    - `gp`: the global pointer of the binary
    - `sp`: the stack pointer of the binary
    - `region`: the region of the binary, which can be one of the following:
        - `'NTSC'`: NTSC region
        - `'PAL'`: PAL region
- `PCSX.Binary.pack(src, dest, addr, pc, gp, sp, options)`: compresses the input binary stream into a self-decompressing stream. The input must be a `File` object, and the output must be a `File` object. The `addr` is the address that the binary will be loaded at. The `pc`, `gp`, and `sp` are the entry point, global pointer, and stack pointer of the binary. The `options` is an optional table with the following optional fields:
    - `tload`: the address that the compressed binary will be loaded at. If not specified, it will be set to a suitable address. Not specifying this will generate an in-place decompression binary, which doesn't require much extra memory. When specifying this, the whole output stream needs to be loaded at this specific address, and the decompression code will be located at its beginning, meaning both the entry point and the loading addresses will be the same.
    - `booty`: a boolean specifying that the output stream will be suitable to boot as a PIO bytestream. Incompatible with `tload` or `raw`.
    - `shell`: a boolean specifying that the output stream will attempt to reboot the machine and load the binary, which can be useful when resetting the kernel.
    - `raw`: a boolean specifying that the output stream will be a raw binary, without a PS-EXE header. It doesn't make sense to use this without `tload`.
- `PCSX.Binary.createExe(src, dest, addr, pc, gp, sp)`: creates a PS-EXE binary from the input binary stream. The input must be a `File` object, and the output must be a `File` object. The `addr` is the address that the binary will be loaded at. The `pc`, `gp`, and `sp` are the entry point, global pointer, and stack pointer of the binary.

The above methods can be used for example the following way:

```lua
local src = PCSX.getCurrentIso():createReader():open('SLUS_012.34;1')

local m4g = Support.File.mem4g()
local info = PCSX.Binary.load(src, m4g)
local asm = PCSX.Assembler.New()
asm:parse [[
    lui   $a0, 0x8001
    addiu $a0, 0x1234
]]:compileToFile(m4g, 0x80045678)
local bytes = m4g:subFile(m4g:lowestAddress(), m4g:actualSize())

local dst = Support.File.open('compressed-from-lua.ps-exe', 'TRUNCATE')

PCSX.Binary.pack(bytes, dst, m4g:lowestAddress(), info.pc, info.gp, info.sp)
```

Additionally, the `PCSX.Misc` module has the following functions:

- `PCSX.Misc.uclPack(src, dest)`: compresses the input binary stream into a ucl-compressed stream. The input must be a `File` object, and the output must be a `File` object. The output stream will be written at its current write pointer, and will be compressed using the UCL-NRV2E compression algorithm, which is a variant of the UCL compression algorithm. The output stream can be decompressed in-place with very little memory overhead. Simply place the compressed data at the end of the decompression buffer + 16 bytes. The stream doesn't require to be aligned in any particular way.
- `PCSX.Misc.writeUclDecomp(dest)`: writes a MIPS UCL-NRV2E decompression routine to the output `File` object, at its current write pointer. The function returns the number of bytes written, which at the moment is 340 bytes. The code is position independent, and has the following function signature:
    - `void decompress(uint8_t* src, uint8_t* dest);`