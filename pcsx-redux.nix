{
  stdenv,
  lib,
  fetchFromGitHub,
  libuv,
  zlib,
  curl,
  ffmpeg,
  glfw3,
  capstone,
  freetype,
  libX11,
  pkg-config,
  imagemagick,
  # luajit,
  luajitPackages,
  multipart-parser-c,
  fmt,
  magic-enum,
  miniaudio,
  gtest,
  tl-expected,
  elfio,
  tracy,
  md4c,
  stb,
  uriparser,
  ucl,
  llhttp,

  debugBuild ? false,
  src
}:
let
# get rid of this nonsense
  zep = fetchFromGitHub {
    owner = "grumpycoders";
    repo = "zep";
    rev = "86ea3c7019f45ccd4a13503bf7d98a396e8f0193";
    hash = "sha256-6NmUlOHkRQvCgbATcNxnFrfA2ZWROPYN8Vpd10k6Z2g=";
  };
  nanosvg = fetchFromGitHub {
    owner = "grumpycoders";
    repo = "nanosvg";
    rev = "f0a3e1034dd22e2e87e5db22401e44998383124e";
    hash = "sha256-af11kAga6Ru2rPgrfcYswXNy9etvH3J9FX2T0I0++ew=";
  };
  nanovg = fetchFromGitHub {
    owner = "grumpycoders";
    repo = "nanovg";
    rev = "7c021819bbd4843a1a3091fe47346d3fcb2a3e1a";
    hash = "sha256-gZHbNuDkLXlLlXZZpLBHcbwzTfeBBkLY7xl4L5yr2lY=";
  };
  imgui-md = fetchFromGitHub {
      owner = "mekhontsev";
      repo = "imgui_md";
      rev = "8ca75c5f7663f314821e3d0b2c51011792bee68f";
      hash = "sha256-uxhY81DWLRRCceYn9khk3rwzT+2f9PNMIMT9OrkPfFc=";
  };
  xbyak = fetchFromGitHub {
      owner = "herumi";
      repo = "xbyak";
      rev = "2fb843c3287918038c8f76276a590c25cc7ec5ee";
      hash = "sha256-XZce+kEZ7dipI19WY43ycOjzM2dZyANMEN5+GhoNYUk=";
  };
  luafs = fetchFromGitHub {
      owner = "lunarmodules";
      repo = "luafilesystem";
      rev = "912e06714fc276c15b4d5d1b42bd2b11edb8deff";
      hash = "sha256-BShByo2NhVrOHDPze/JXfeFWq36PFrI2HVugR2MDB0A=";
  };
  luajit = fetchFromGitHub {
      owner = "grumpycoders";
      repo = "luajit";
      rev = "66fadd16a51955cfbd770de62806cfbdd7c6c818";
      hash = "sha256-nFlDr79GC8MsL6ausAsEPJwL8OJrFydB37tpD5mS1C8=";
  };
  imgui = fetchFromGitHub {
      owner = "ocornut";
      repo = "imgui";
      rev = "368123ab06b2b573d585e52f84cd782c5c006697";
      hash = "sha256-6VOs7a31bEfAG75SQAY2X90h/f/HvqZmN615WXYkUOA=";
  };
  sdl-db = fetchFromGitHub {
      owner = "mdqinc";
      repo = "SDL_GameControllerDB";
      rev = "b1e342774cbb35467dfdd3634d4f0181a76cbc89";
      hash = "sha256-LYvO+chDVo6D++fuFbxqSRltGW3y82SESmtFj39TdSA=";
  };
  # commit = "faee80688fa03d924437118b28720184b7b58de1";
in stdenv.mkDerivation {
  pname = "pcsx-redux";
  version = "0.99test";
  inherit src;
/*
  src = fetchFromGitHub {
    owner = "grumpycoders";
    # owner = "NotExactlySiev";
    repo = "pcsx-redux";
    rev = commit;
    hash = "sha256-qbpeNCv7jsRBg7GOn/EAm1A2K3F/zHuMHF/bBOb9q0o=";
  };
*/

  postUnpack = ''
    # rmdir source/third_party/miniaudio
    # rmdir source/third_party/zep
    # rmdir source/third_party/nanosvg
    # rmdir source/third_party/nanovg
    # rmdir source/third_party/imgui
    # rmdir source/third_party/imgui_md
    # rmdir source/third_party/xbyak
    # rmdir source/third_party/luafilesystem
    # rmdir source/third_party/luv
    # rmdir source/third_party/SDL_GameControllerDB
    # rmdir source/third_party/tracy
    # rmdir source/third_party/luajit

    cp -r ${miniaudio.out} source/third_party/miniaudio
    cp -r ${zep.out} source/third_party/zep
    cp -r ${nanosvg.out} source/third_party/nanosvg
    cp -r ${nanovg.out} source/third_party/nanovg
    cp -r ${imgui.out} source/third_party/imgui
    cp -r ${imgui-md.out} source/third_party/imgui_md
    cp -r ${xbyak.out} source/third_party/xbyak
    cp -r ${luafs.out} source/third_party/luafilesystem
    cp -r ${sdl-db.out} source/third_party/SDL_GameControllerDB
    cp -r ${tracy.src} source/third_party/tracy
    cp -r ${luajit.out} source/third_party/luajit

    chmod -R +w source/third_party/miniaudio
    chmod -R +w source/third_party/zep
    chmod -R +w source/third_party/nanosvg
    chmod -R +w source/third_party/nanovg
    chmod -R +w source/third_party/imgui
    chmod -R +w source/third_party/imgui_md
    chmod -R +w source/third_party/luafilesystem
    chmod -R +w source/third_party/SDL_GameControllerDB
    chmod -R +w source/third_party/tracy
    chmod -R +w source/third_party/luajit
 '';

   patches = [
     ./001-patch.diff
   ];

  nativeBuildInputs = [
    pkg-config
    imagemagick
  ];

  buildInputs = [
    stb
    ucl
    #imgui
    md4c
    # luajit
    # luajitPackages.lpeg
    #luajitPackages.luafilesystem
    #luajitPackages.lua-protobuf
    luajitPackages.libluv
    multipart-parser-c
    fmt
    magic-enum
    gtest
    tl-expected
    elfio
    libuv
    tracy
    curl.dev
    zlib
    ffmpeg.dev
    glfw3
    capstone
    freetype.dev
    uriparser
    libX11
    llhttp
  ];

  runtimeDependencies = [
    # zlib
  ];

  makeFlags = [
    "DESTDIR=$(out)"
  ];

  # TODO: learn how to use separate debug info
  dontStrip = debugBuild;
  enableDebugging = debugBuild;
  
  enableParallelBuilding = true;
  NIX_BUILD_CORES = 10;

  meta = {
    homepage = "https://pcsx-redux.consoledev.net";
    description = "PlayStation 1 emulator and debugger";
    #license = lib.licenses.gpl3Only;
    mainProgram = "pcsx-redux";
    #maintainers = with lib.maintainers; [ guibou AndersonTorres ];
    platforms = lib.platforms.linux;
  };
}
