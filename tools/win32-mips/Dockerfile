# escape=`

# Dockerfile to generate the Windows g++-mipsel-none-elf-11.3.0.zip package.

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

ARG BINUTILS=https://ftp.gnu.org/gnu/binutils/binutils-2.38.tar.xz
ARG GCC=https://ftp.gnu.org/gnu/gcc/gcc-11.3.0/gcc-11.3.0.tar.xz

RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
    Invoke-WebRequest $env:BINUTILS -OutFile "C:\Windows\Temp\binutils-2.38.tar.xz"; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList e, "C:\Windows\Temp\binutils-2.38.tar.xz", `-y, `-oC:\Windows\Temp\ -NoNewWindow -PassThru -Wait; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList x, "C:\Windows\Temp\binutils-2.38.tar", `-y, `-oC:\ -NoNewWindow -PassThru -Wait; `
    Remove-Item @('C:\Windows\Temp\*', 'C:\Users\*\Appdata\Local\Temp\*') -Force -Recurse;

RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
    Invoke-WebRequest $env:GCC -OutFile "C:\Windows\Temp\gcc-11.3.0.tar.xz"; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList e, "C:\Windows\Temp\gcc-11.3.0.tar.xz", `-y, `-oC:\Windows\Temp\ -NoNewWindow -PassThru -Wait; `
    Start-Process -FilePath "C:\7-Zip\7z.exe" -ArgumentList x, "C:\Windows\Temp\gcc-11.3.0.tar", `-y, `-oC:\ -NoNewWindow -PassThru -Wait; `
    Remove-Item @('C:\Windows\Temp\*', 'C:\Users\*\Appdata\Local\Temp\*') -Force -Recurse;

ENV MSYSTEM MINGW64

RUN C:\msys64\usr\bin\bash.exe -l -c 'cd /c/binutils-2.38 && /c/binutils-2.38/configure --target=mipsel-none-elf --disable-multilib --disable-nls --disable-werror --prefix=/DIST || (cat /BUILD/config.log && exit 1)'

RUN C:\msys64\usr\bin\bash.exe -l -c 'cd /c/binutils-2.38/libiberty && sed -i s/\\\\buint\\\\b/unsigned/ rust-demangle.c'

RUN C:\msys64\usr\bin\bash.exe -l -c 'make -C /c/binutils-2.38 all'
RUN C:\msys64\usr\bin\bash.exe -l -c 'make -C /c/binutils-2.38 install-strip'
RUN C:\msys64\usr\bin\bash.exe -l -c 'cp /c/binutils-2.38/COPYING* /DIST'

RUN C:\msys64\usr\bin\bash.exe -l -c 'mkdir /c/gcc-11.3.0/build && cd /c/gcc-11.3.0/build && ../configure --target=mipsel-none-elf --without-isl --disable-nls --disable-threads --disable-shared --disable-libssp --disable-libstdcxx-pch --disable-libgomp --disable-werror --without-headers --with-as=/DIST/bin/mipsel-none-elf-as --with-ld=/DIST/bin/mipsel-none-elf-ld --enable-languages=c,c++ --prefix=/DIST || (cat /BUILD/config.log && exit 1)'
RUN C:\msys64\usr\bin\bash.exe -l -c 'make -C /c/gcc-11.3.0/build all-gcc'
RUN C:\msys64\usr\bin\bash.exe -l -c 'make -C /c/gcc-11.3.0/build all-target-libgcc'
RUN C:\msys64\usr\bin\bash.exe -l -c 'make -C /c/gcc-11.3.0/build install-strip-gcc install-strip-target-libgcc'

RUN C:\msys64\usr\bin\bash.exe -l -c 'for t in cat cp echo mkdir rm touch ; do cp /usr/bin/$t.exe /DIST/bin ; done'
RUN C:\msys64\usr\bin\bash.exe -l -c 'cp /mingw64/bin/mingw32-make.exe /DIST/bin/make.exe'
RUN C:\msys64\usr\bin\bash.exe -l -c 'cd /DIST && find . -name *.exe | while read bin ; do ldd $bin | cut -f2 -d\> | cut -f2 -d\  | grep -v /c/Windows/S | while read f ; do cp $f $(dirname $bin) ; done ; done'

RUN C:\msys64\usr\bin\bash.exe -l -c 'cd /DIST && zip /c/g++-mipsel-none-elf-11.3.0.zip . -r'

CMD C:\msys64\usr\bin\bash.exe -l
