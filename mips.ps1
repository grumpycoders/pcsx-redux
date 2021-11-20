<#
Copyright 2021 PCSX-Redux authors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the
Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#>

if ((-not (Get-Variable PSVersionTable -Scope Global -ErrorAction SilentlyContinue)) -or ($PSVersionTable.PSVersion.Major -lt 5)) {
    Write-Host "Your version of PowerShell is too old."
    Write-Host "mips-ps requires a least PowerShell 5.0"
    Write-Host "You need to download and install Windows Management Framework 5.0+"
    exit
}

if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Host "The prebuilt mips toolchains can only work on a 64 bits version of Windows,"
    Write-Host "but you're running a 32 bits version. Please install the 64 bits version of"
    Write-Host "Windows and try again."
    exit
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-AbsolutePath($Path) {
    $Path = [System.IO.Path]::Combine(((pwd).path), ($Path))
    $Path = [System.IO.Path]::GetFullPath($Path)
    return $Path.TrimEnd("\/")
}

# Adds a path to the user's PATH environment variable.
function Add-Path($Path) {
    $UserPath = [environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -eq $NULL) {
        return
    }
    foreach ($Fragment in $UserPath.split(";")) {
        if ($Fragment -like $Path) {
            return
        }
    }
    [environment]::SetEnvironmentVariable("PATH", $UserPath + ";" + $Path, "User")
}

function MkDir-p($Path) {
    $FullPath = "\\?\" + $Path
    if (-not (Test-Path -Path $FullPath)) {
        New-Item -ItemType directory -Path $FullPath | Out-Null
    }
}

function Usage() {
    Write-Host "Usage:"
    Write-Host "  mips install <version>"
    Write-Host "  mips use <version>"
    Write-Host "  mips ls"
    Write-Host "  mips ls-remote"
    Write-Host "  mips version"
    Write-Host "  mips self-install"

    exit
}

function Download-Index($Path) {
    $IndexFile = $Path + "/index.json"
    $FullURL = $MipsBaseURL + "/index.json"
    Invoke-WebRequest -ContentType "application/octet-stream" -Uri $FullURL -OutFile $IndexFile
}

function Sort-Versions($Data) {
    $Versions = @()
    ForEach ($Version in $Data) {
        [Int]$Major, [Int]$Minor, [Int]$Patch = $Version.version.TrimStart("v").Split(".")
        $Key = $Major * 10000 + $Minor * 100 + $Patch
        $Version | Add-Member Key $Key
        $Versions += $Version
    }
    return $Versions | Sort-Object -Descending -Property Key
}

# Downloads the index, and assign a version number to it that can be easily sorted.
# This way doing mips install 8 will install the latest version of 8.
function Load-Index($Path) {
    $IndexFile = $Path + "/index.json"
    if (-not (Test-Path $IndexFile)) {
        Download-Index($Path)
    }
    $RawData = (Get-Content $IndexFile) -join "`n" | ConvertFrom-Json
    return Sort-Versions $RawData
}

function New-TempDir {
    $TempDir = [System.IO.Path]::GetTempPath()
    [string]$Random = [System.Guid]::NewGuid()
    $TempDir = Join-Path $TempDir $Random
    New-Item -ItemType Directory -Path $TempDir | Out-Null
    return $TempDir
}

# Downloads the list of releases, and attempts to find a version that matches the
# one specified by $Version. Returns a structure with the information for that specific
# version. The index is this one: https://static.grumpycoder.net/pixel/mips/index.json
function Locate-Version($Version) {
    $VersionString = "v" + $Version
    $Version = $NULL
    For ($run = 0; $run -le 1; $run++) {
        $Index = Load-Index $cwd
        ForEach ($Iterator in $Index) {
            if ($Iterator.version.StartsWith($VersionString)) {
                $Version = $Iterator
                break
            }
        }
        if ($Version -eq $NULL) {
            Download-Index $cwd
        } else {
            $Version | Add-Member File $File
            return $Version
        }
    }

    Write-Host "Mips toolchain version $VersionString not found"
    return $NULL
}

# Will change the symlink to another version of the toolchain. We're currently not checking if that
# version is indeed installed. TODO: check if the version is actually there.
function Use($Version) {
    [string]$Version = $Version
    if (!$Version.StartsWith("v")) {
        $Installed = Get-ChildItem $VersionsPath | Select-Object Name
        $Versions = @()
        ForEach ($Iterator in $Installed) {
            $Object = New-Object PSObject
            $Object | Add-Member version $Iterator.Name
            $Versions += $Object
        }
        $Versions = Sort-Versions $Versions
        $Version = "v" + $Version
        ForEach ($Iterator in $Versions) {
            if ($Iterator.version.StartsWith($Version)) {
                $Version = $Iterator.version
                break
            }
        }
    }
    $VersionPath = $VersionsPath + "/" + $Version
    if (Test-Path -Path $symlink) {
        Remove-Item -Path $symlink -Recurse -Force
    }
    New-Item -Force -Path $symlink -ItemType Junction -Value $VersionPath
}

# Will attempt to download and install the version of the mips toolchain specified by $Version.
function Install($Version) {
    $Version = Locate-Version $Version
    if ($Version -eq $NULL) {
        return $FALSE
    }

    $TempDir = New-TempDir
    $OutputDir = $cwd + "/versions/" + $Version.version

    $ToolchainURL = $MipsBaseURL + "g++-mipsel-none-elf-" + $Version.version.TrimStart("v") + ".zip"
    $OutputToolchain = $TempDir + "/gcc.zip"
    Write-Host "Downloading toolchain package from $ToolchainURL..."
    Invoke-WebRequest -ContentType "application/octet-stream" -Uri $ToolchainURL -OutFile $OutputToolchain

    $GdbURL = $GdbBaseURL + "gdb-multiarch-" + $Version.version + ".zip"
    $OutputGDB = $TempDir + "/gdb.zip"
    Write-Host "Downloading gdb package from $GdbURL..."
    Invoke-WebRequest -ContentType "application/octet-stream" -Uri $ToolchainURL -OutFile $OutputGDB

    Write-Host "Extracting toolchain package..."
    Expand-Archive -Path $OutputToolchain -DestinationPath $OutputDir -Force
    Write-Host "Extracting gdb package..."
    Expand-Archive -Path $OutputGDB -DestinationPath $OutputDir -Force

    Remove-Item -Path $OutputToolchain -Force | Out-Null
    Remove-Item -Path $OutputGDB -Force | Out-Null
    $VersionString = $Version.version

    Use $VersionString
    return $TRUE
}

$dest = Get-AbsolutePath ([Environment]::GetFolderPath('ApplicationData') + "/mips")
$me = $MyInvocation.Value.MyCommand
if ($me -eq $NULL) {
    $me = $MyInvocation.InvocationName
}

$MipsBaseURL = "https://static.grumpycoder.net/pixel/mips/"
$GdbBaseURL = "https://static.grumpycoder.net/pixel/gdb-multiarch-windows/"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$MyURI = "https://raw.githubusercontent.com/grumpycoders/pcsx-redux/main/mips.ps1"

# If we're invoked from the installer shortcut, we're going to redownload ourselves
# and install ourselves. That's a bit redundant, but, sure.
if ($me -eq "&") {
    $me = [System.IO.Path]::GetTempFileName()
    Invoke-WebRequest -Uri $MyURI -OutFile $me
    $cmd = "self-install"
    $symlink = $dest + "/mips"
    $VersionsPath = $dest + "/versions"
} else {
    $cwd = Get-AbsolutePath (Split-Path $me)
    $symlink = $cwd + "/mips"
    $VersionsPath = $cwd + "/versions"

    $cmd = $args[0]
    if ($args.Length -eq 0) {
        Usage
        return
    }
}

# Globals for PowerShell behavior
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "stop"

switch ($cmd) {
    "install" {
        if ($args[1] -eq $NULL) {
            Usage
        }
        Install $args[1] | Out-Null
    }
    "use" {
        if ($args[1] -eq $NULL) {
            Usage
        }
        Use $args[1] | Out-Null
    }
    "ls" {
        Get-ChildItem $VersionsPath | Select-Object Name
    }
    "ls-remote" {
        Download-Index $cwd
        if ($args[1] -eq $NULL) {
            Load-Index $cwd | Sort-Object -Property Key | Select-Object version
        } else {
            Load-Index $cwd | Sort-Object -Property Key | Where-Object {$_.lts} | Select-Object version
        }
    }
    "version" {
        Write-Host "v0.1.0"
    }
    "self-install" {
        if ($cwd -like $dest) {
            Write-Host "This is already installed."
        } else {
            Write-Host "Installing..."
            MkDir-p $dest
            MkDir-p $VersionsPath
            Copy-Item -Force $me $dest/mips.ps1
            Set-Content -Path $dest/mips.cmd -Value "@PowerShell -ExecutionPolicy Unrestricted %~dp0/mips.ps1 %*"
            Add-Path $dest
            Add-Path $symlink\bin
            Write-Host "Done. Open a new console and type mips."
        }
    }
    default {
        Write-Host "Unknown command $cmd"
        Usage
    }
}
