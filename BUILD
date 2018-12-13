cc_binary(
    name = "pcsx-redux",
    srcs = glob([
        "src/**/*.c",
        "src/**/*.cc",
        "src/**/*.h",
    ]),
    includes = ["src/core"],
    deps = ["@com_github_madler_zlib//:z"],
)
