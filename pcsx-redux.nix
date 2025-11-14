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
  uriparser,
  ucl,
  llhttp,
  zip,

  src,
  debugBuild ? false,
  platforms,
  gccMips,
  withOpenbios ? true,
}:
let
  # TODO: read the revs from elsewhere to avoid duplication
  submodules = [
    ({
      owner = "grumpycoders";
      repo = "zep";
      rev = "86ea3c7019f45ccd4a13503bf7d98a396e8f0193";
      hash = "sha256-6NmUlOHkRQvCgbATcNxnFrfA2ZWROPYN8Vpd10k6Z2g=";
    })
    ({
      owner = "grumpycoders";
      repo = "nanosvg";
      rev = "f0a3e1034dd22e2e87e5db22401e44998383124e";
      hash = "sha256-af11kAga6Ru2rPgrfcYswXNy9etvH3J9FX2T0I0++ew=";
    })
    ({
      owner = "grumpycoders";
      repo = "nanovg";
      rev = "7c021819bbd4843a1a3091fe47346d3fcb2a3e1a";
      hash = "sha256-gZHbNuDkLXlLlXZZpLBHcbwzTfeBBkLY7xl4L5yr2lY=";
    })
    ({
      owner = "mekhontsev";
      repo = "imgui_md";
      rev = "8ca75c5f7663f314821e3d0b2c51011792bee68f";
      hash = "sha256-uxhY81DWLRRCceYn9khk3rwzT+2f9PNMIMT9OrkPfFc=";
    })
    ({
      owner = "herumi";
      repo = "xbyak";
      rev = "2fb843c3287918038c8f76276a590c25cc7ec5ee";
      hash = "sha256-XZce+kEZ7dipI19WY43ycOjzM2dZyANMEN5+GhoNYUk=";
    })
    ({
      owner = "lunarmodules";
      repo = "luafilesystem";
      rev = "912e06714fc276c15b4d5d1b42bd2b11edb8deff";
      hash = "sha256-BShByo2NhVrOHDPze/JXfeFWq36PFrI2HVugR2MDB0A=";
    })
    ({
      owner = "grumpycoders";
      repo = "luajit";
      rev = "66fadd16a51955cfbd770de62806cfbdd7c6c818";
      hash = "sha256-nFlDr79GC8MsL6ausAsEPJwL8OJrFydB37tpD5mS1C8=";
    })
    ({
      owner = "ocornut";
      repo = "imgui";
      rev = "368123ab06b2b573d585e52f84cd782c5c006697";
      hash = "sha256-6VOs7a31bEfAG75SQAY2X90h/f/HvqZmN615WXYkUOA=";
    })
    ({
      owner = "mdqinc";
      repo = "SDL_GameControllerDB";
      rev = "b1e342774cbb35467dfdd3634d4f0181a76cbc89";
      hash = "sha256-LYvO+chDVo6D++fuFbxqSRltGW3y82SESmtFj39TdSA=";
    })
    ({
      owner = "nothings";
      repo = "stb";
      rev = "ae721c50eaf761660b4f90cc590453cdb0c2acd0";
      hash = "sha256-BIhbhXV7q5vodJ3N14vN9mEVwqrP6z9zqEEQrfLPzvI=";
    })
  ] ++ lib.optional stdenv.hostPlatform.isAarch {
    owner = "grumpycoders";
    repo = "vixl";
    rev = "53ad192b26ddf6edd228a24ae1cffc363b442c01";
    hash = "sha256-p9Z2lFzhqnHnFWfqT6BIJBVw2ZpkVIxykhG3jUHXA84=";
  } ++ lib.optional withOpenbios {
    owner = "grumpycoders";
    repo = "uC-sdk";
    rev = "69e06871824e2d62069487a7426ded09090ceb69";
    hash = "sha256-VamLhNtXxilcvd6ch76ronhB7DcKfw2eL7CuLwHFbp8=";
  };

  fetchSubmodule = { owner, repo, rev, hash }@args:
      "cp -ruT --no-preserve=all ${(fetchFromGitHub args).out} source/third_party/${repo}";

in stdenv.mkDerivation {
  pname = "pcsx-redux";
  version = "0.99test";
  inherit src;

  postUnpack = ''
    cp -ruT --no-preserve=all ${miniaudio.out} source/third_party/miniaudio
    cp -ruT --no-preserve=all ${tracy.src} source/third_party/tracy
  '' + builtins.concatStringsSep "\n" (map fetchSubmodule submodules);

  nativeBuildInputs = [
    pkg-config
    imagemagick
  ] ++ lib.optionals withOpenbios [
    # unwrap them
    gccMips.cc
    gccMips.bintools.bintools
    zip
  ];

  buildInputs = [
    ucl
    md4c
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

  makeFlags = [
    (lib.optionalString withOpenbios "openbios")
    "pcsx-redux"
    "PREFIX=mipsel-unknown-none-elf"
  ];

  installFlags = [
    "install"
    (lib.optionalString withOpenbios "install-openbios")
    "DESTDIR=$(out)"
  ];

  # TODO: learn how to use separate debug info
  dontStrip = debugBuild;
  enableDebugging = debugBuild;

  enableParallelBuilding = true;

  meta = {
    homepage = "https://pcsx-redux.consoledev.net";
    description = "PlayStation 1 emulator and debugger";
    mainProgram = "pcsx-redux";
    inherit platforms;
  };
}
