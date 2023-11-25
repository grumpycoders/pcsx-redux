# Web server

A web server can be activated. This allows the use of a REST api to access various features. The server only handles up to HTTP/1.1, without SSL support.

## Activation

You can activate the web server by going to `Configuration > Emulation > Enable Web Server`

## REST API

By default, the server listens for incoming connection on `localhost:8080`. The port can be changed in the same settings above.

These GET methods are available:

| URL | Function |
| :- | :- |
| [/api/v1/gpu/vram/raw](http://localhost:8080/api/v1/gpu/vram/raw) | Dump VRAM  |
| [/api/v1/cpu/ram/raw](http://localhost:8080/api/v1/cpu/ram/raw) | Dump RAM |
| [/api/v1/execution-flow](http://localhost:8080/api/v1/execution-flow) | Emulation Status |

The following POST methods are available:

`/api/v1/gpu/vram/raw?x=<value>&y=<value>&width=<value>&height=<value>`

The above needs to also send a form with binary contents. This will partially update the VRAM with the corresponding pixels. The updated rectangle has to be within the 1024x512 16bpp VRAM. The pixels need to be in 16bpp format, meaning the server is expecting exactly `width * height * 2` bytes in the form data. The server will properly parse requests with `Content-Type: multipart/form-data`, but raw bytes in the request body without this header is also acceptable. Any invalid query will result in a 400 error.

`/api/v1/cpu/ram/raw?offset=<value>&size=<value>`

The above needs to also send a form with binary contents, which will update the RAM at the specified offset. Offset is expected to be a number from [0, 0x1FFFFF] in case of running redux with 2MB RAM, or [0, 0x7FFFFF] in case the 8MB memory expansion is enabled. The value of size + offset must not exceed the total space in the RAM.

`/api/v1/assembly/symbols?function=<value>`

| Value | Function |
| :- | :- |
| reset | Resets the symbols loaded in redux |
| upload | Uploads a `.map` file to redux |

The above expects a `.map` file with symbols and addresses, which will be merged with the current symbols already loaded in redux. The map file should contain a pair of `symbol address` for each line. e.g `Foo 80010000` would load the symbol `Foo` in the address `0x80010000`.

`/api/v1/cpu/cache?function=<value>`

| Value | Function |
| :- | :- |
| flush | Flushes the CPU cache |

`/api/v1/execution-flow?function=<value>&type=<value>`

| Value | Type | Function |
| :- | :- | :- |
| pause | - | Pauses the emulator. |
| start | - | Starts/Resumes the emulator. |
| resume | - | Starts/Resumes the emulator. |
| reset | hard | Hard resets the emulator. Equivalent to a power cycle of the console. |
| reset | soft | Soft resets the emulator. Equivalent to pressing the reset button. |

`/api/v1/cd/patch?filename=<value>`

The above needs to also send a form with binary contents, which will patch the currently loaded iso file with the contents of the form. The server will look for the given filename in the iso file, and patch its contents. A ppf file will be written out as a result. All changes are cumulative. If the file is not found, a 404 error will be returned. The file name is case sensitive, and must be a valid ISO9660 filename, which means it can only contain uppercase letters, numbers, and underscores, and ends with `;1`.

For example:

```bash
$ curl -F file=@newsystem.cnf http://localhost:8080/api/v1/cd/patch?filename=SYSTEM.CNF;1
```

`/api/v1/cd/patch?sector=<value>&mode=<value>`

The above needs to also send a form with binary contents, which will patch the currently loaded iso file with the contents of the form. The iso sectors starting at the given value will be written to. The `mode` argument is optional, and can be of the following values:

| Value | Function |
| :- | :- |
| GUESS | Tries to guess the sector's mode. This is the default. |
| RAW | Writes the full sectors with no decoration, 2352 bytes per sector. |
| M2_RAW | Writes 2336 bytes per sector, with the first 16 bytes being the subheader. |
| M2_FORM1 | Writes 2048 bytes per sector. Will not update the subheader. |
| M2_FORM2 | Writes 2324 bytes per sector. Will not update the subheader. |

A ppf file will be written out as a result. All changes are cumulative.

