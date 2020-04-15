@echo off
set OLDCWD=%cd%
cd ..\..\..
set ROOT=%cd%
cd %OLDCWD%
docker run --rm -t -i -v "%ROOT%:/project" grumpycoders/pcsx-redux-build:latest make -C src/mips/openbios clean all
