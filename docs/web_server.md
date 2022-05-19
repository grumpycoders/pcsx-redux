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

The following POST methods are available:

`/api/v1/gpu/vram/raw?x=<value>&y=<value>&width=<value>&height=<value>`

The above needs to also send a form with binary contents. This will partially update the VRAM with the corresponding pixels. The updated rectangle has to be within the 1024x512 16bpp VRAM. The pixels need to be in 16bpp format, meaning the server is expecting exactly `width * height * 2` bytes in the form data. The server will properly parse requests with `Content-Type: multipart/form-data`, but raw bytes in the request body without this header is also acceptable. Any invalid query will result in a 400 error.
