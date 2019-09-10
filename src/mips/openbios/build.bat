@echo off
docker run --rm -t -i -v "%~dp0\..:/project" grumpycoders/pcsx-redux-build:latest make -C openbios clean all
