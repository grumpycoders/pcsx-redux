@echo off
set OLDCWD=%cd%
cd %~dp0
cd ..\..\..
set ROOT=%cd%
cd %OLDCWD%
%ROOT%\dockermake.bat all -j4
