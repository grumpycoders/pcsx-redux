# escape=`

# Dockerfile to generate the Windows gdb-multiarch-10.1.zip package.

FROM mcr.microsoft.com/windows/servercore:ltsc2019
WORKDIR C:\windows\temp
SHELL ["powershell", "-command"] 

RUN Invoke-WebRequest -UserAgent 'DockerCI' -outfile 7zsetup.exe http://www.7-zip.org/a/7z1604-x64.exe

RUN Start-Process .\7zsetup -ArgumentList '/S /D=c:/7-zip' -Wait

ARG MSYS2_X86_64="https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-base-x86_64-latest.tar.xz"

RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
    Invoke-WebRequest $env:MSYS2_X86_64 -OutFile "C:\Windows\Temp\msys2-x86_64.tar.xz"; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList e, "C:\Windows\Temp\msys2-x86_64.tar.xz", `-oC:\Windows\Temp\ -NoNewWindow -PassThru -Wait; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList x, "C:\Windows\Temp\msys2-x86_64.tar", `-oC:\ -NoNewWindow -PassThru -Wait; `
    Remove-Item @('C:\Windows\Temp\*', 'C:\Users\*\Appdata\Local\Temp\*') -Force -Recurse;

RUN Write-Host 'Updating MSYSTEM and MSYSCON ...'; `
    [Environment]::SetEnvironmentVariable('MSYSTEM', 'MSYS2', [EnvironmentVariableTarget]::Machine); `
    [Environment]::SetEnvironmentVariable('MSYSCON', 'defterm', [EnvironmentVariableTarget]::Machine);

RUN C:\msys64\usr\bin\bash.exe -l -c 'exit 0'; `
    Get-Process | Where-Object {$_.Path -Like 'C:\msys64\*'} | Stop-Process -Force -PassThru | Wait-Process; `
    Get-Process @('bash', 'dirmngr', 'gpg-agent', 'pacman') -ErrorAction SilentlyContinue | Stop-Process -Force -PassThru | Wait-Process; `
    Write-Host 'Eating error.';

RUN C:\msys64\usr\bin\bash.exe -l -c 'exit 0'; `
    C:\msys64\usr\bin\bash.exe -l -c 'pacman -Syuu --needed --noconfirm'; `
    C:\msys64\usr\bin\bash.exe -l -c 'pacman -Syu  --needed --noconfirm'; `
    C:\msys64\usr\bin\bash.exe -l -c 'pacman -Su   --needed --noconfirm'; `
    C:\msys64\usr\bin\bash.exe -l -c 'pacman -Scc --noconfirm'; `
    C:\msys64\usr\bin\bash.exe -l -c 'exit 0'; `
    Get-Process | Where-Object {$_.Path -Like 'C:\msys64\*'} | Stop-Process -Force -PassThru | Wait-Process; `
    Get-Process @('bash', 'dirmngr', 'gpg-agent', 'pacman') -ErrorAction SilentlyContinue | Stop-Process -Force -PassThru | Wait-Process; `
    Write-Host 'Eating error.';

RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -S --needed --noconfirm mingw-w64-x86_64-toolchain'
RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -S --needed --noconfirm automake autoconf make intltool libtool zip unzip'
RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -S --needed --noconfirm bison diffutils texinfo'
RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -S --needed --noconfirm mingw-w64-x86_64-expat mingw-w64-x86_64-ncurses'
RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -S --needed --noconfirm mingw-w64-x86_64-xxhash mingw-w64-x86_64-pdcurses'
RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -S --needed --noconfirm mingw-w64-x86_64-python mingw-w64-x86_64-readline'
RUN C:\msys64\usr\bin\bash.exe -l -c 'pacman -Scc --noconfirm'

ARG GDB=https://ftp.gnu.org/gnu/gdb/gdb-10.1.tar.xz

RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
    Invoke-WebRequest $env:GDB -OutFile "C:\Windows\Temp\gdb-10.1.tar.xz"; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList e, "C:\Windows\Temp\gdb-10.1.tar.xz", `-oC:\Windows\Temp\ -NoNewWindow -PassThru -Wait; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList x, "C:\Windows\Temp\gdb-10.1.tar", `-oC:\ -NoNewWindow -PassThru -Wait; `
    Remove-Item @('C:\Windows\Temp\*', 'C:\Users\*\Appdata\Local\Temp\*') -Force -Recurse;

ENV MSYSTEM MINGW64

RUN C:\msys64\usr\bin\bash.exe -l -c 'mkdir /BUILD && cd /BUILD && /c/gdb-10.1/configure --disable-gdbtk --disable-shared --disable-readline --with-system-readline --with-expat --with-system-zlib --without-guile --without-babeltrace --enable-tui --with-lzma --without-python --with-xxhash --with-mpfr --enable-64-bit-bfd --enable-targets=all --disable-sim --prefix=/DIST || (cat /BUILD/config.log && exit 1)'

RUN C:\msys64\usr\bin\bash.exe -l -c 'LOADLIBES=-lws2_32\ -lbcrypt make -C /BUILD all'
RUN C:\msys64\usr\bin\bash.exe -l -c 'make -C /BUILD install-strip'
RUN C:\msys64\usr\bin\bash.exe -l -c 'cd /DIST/bin && ldd *.exe | cut -f2 -d\> | cut -f2 -d\  | grep mingw64 | while read f ; do cp $f . ; done'
RUN C:\msys64\usr\bin\bash.exe -l -c 'cp /c/gdb-10.1/COPYING* /DIST'
RUN C:\msys64\usr\bin\bash.exe -l -c 'cd /DIST && zip /c/gdb-multiarch-10.1.zip . -r'

CMD C:\msys64\usr\bin\bash.exe -l
