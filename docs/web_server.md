# Web server

A web server can be activated. This allows the use of a REST api to access various features.

## Activation

You can activate the web server by going to `Configuration > Emulation > Enable Web Server`

## REST API

By default, the server listens for incoming connection on `localhost:8080`.

| URL | Function |
| :- | :- |
| [http://localhost:8080/api/v1/gpu/vram/raw](http://localhost:8080/api/v1/gpu/vram/raw) | Dump VRAM  |
| [http://localhost:8080/api/v1/cpu/ram/raw](http://localhost:8080/api/v1/cpu/ram/raw) | Dump RAM |
