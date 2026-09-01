{
  stdenv,
  lib,
  fetchFromGitHub,
  libuv,
  zlib,
  curl,
  ffmpeg,
  sdl3,
  capstone,
  freetype,
  libX11,
  pkg-config,
  imagemagick,
  luajitPackages,
  multipart-parser-c,
  fmt,
  magic-enum,
  gtest,
  tl-expected,
  elfio,
  tracy,
  md4c,
  uriparser,
  ucl,
  llhttp,
  zip,
  libxcb,
  libGL,

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
      rev = "969ae7ea35ae583f215e6f3e724366e0815d58f9";
      hash = "sha256-iblFvaBzZL8lRhAzYh9bmoBW4GzSaMyl35dHpGoyJlw=";
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
      owner = "grumpycoders";
      repo = "imgui_md";
      rev = "193314702e08c9e338a0b9d9346cb93ed4d8b758";
      hash = "sha256-U783p+I1Sy0Dpmz5wRRp6qLiNqcIZ7pUb3Zezgmwhxc=";
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
      rev = "7f89bc0c6529497e0bc45b33467bf6cbcf6e989d";
      hash = "sha256-vSP+KFxSzpzG+nJp0+YF+cDo0eddV3PvAm/jyzFDp14=";
    })
    ({
      owner = "grumpycoders";
      repo = "luajit";
      rev = "07c36331bb4e1140322a6f8d91d53b9c2767ed46";
      hash = "sha256-UNoib5Kf3NxkIKaerZW9NrQ3lyQn0WXvBFRQT+KJrYs=";
    })
    ({
      owner = "ocornut";
      repo = "imgui";
      rev = "b48d1afbe8ee8b238e2961dc363a949dd7304e23";
      hash = "sha256-PknWLxYuXQ73TCFN+eKOJDNLGbg/ZqKSF6mFxkJG6vI=";
    })
    ({
      owner = "mdqinc";
      repo = "SDL_GameControllerDB";
      rev = "b1e342774cbb35467dfdd3634d4f0181a76cbc89";
      hash = "sha256-LYvO+chDVo6D++fuFbxqSRltGW3y82SESmtFj39TdSA=";
    })
    ({
      owner = "taocpp";
      repo = "PEGTL";
      rev = "d7b821b1e5ed6ab321625f50427c4ae0b78909d5";
      hash = "sha256-1hTwoTCkfOX7e0unAlZ8TnYva3enkCgfrfriZfx2AoE=";
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
      "cp -ruT --no-preserve=all ${(fetchFromGitHub args).out} third_party/${repo}";

in stdenv.mkDerivation {
  pname = "pcsx-redux";
  version = "0.99test";
  inherit src;

  preConfigure = ''
    cp -ruT --no-preserve=all ${tracy.src} third_party/tracy
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
    sdl3
    capstone
    freetype.dev
    uriparser
    libX11
    libxcb
    libGL
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
