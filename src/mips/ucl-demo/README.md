This small demo shows how to use the UCL library to compress and decompress data. It is based on the [UCL library](http://www.oberhumer.com/opensource/ucl/) by Markus F.X.J. Oberhumer.

While the UCL library itself is GPL licensed, the decompression code in this demo has been written from scratch, and is released under the MIT license.

The file `ucl-demo.cpp` contains the code for the demo, and should have most of the required documentation to explain how this works. The file `ne2-d.S` contains the decompression code. The file `n2e-d.h` contains the decompression code's header file.

Creating a compressed file can be done using the `compress.lua` script, which for example can be run as follows to compress the `compress.lua` script itself:

```
pcsx-redux -cli -exec "dofile 'compress.lua' compress('compress.lua', 'demo.bin') PCSX.quit()"
```

Then, once the demo.bin file is created, running the demo can be done as follows:

```
pcsx-redux -stdout -noupdate -pcdrv -pcdrvbase . -run -exe ucl-demo.ps-exe
```

The compression code which is bound to Lua simply uses the `ucl_nrv2e_99_compress` API function call from the UCL library, and can be used independently in other projects to create more custom assets.
