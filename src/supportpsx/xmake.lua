local support_root = path.join(os.scriptdir(), "..", "..")

add_rules("mode.debug", "mode.release")

add_requires("fmt", "zlib")
set_languages("c11", "c++26")
includes(path.join(support_root, "src", "support"))

target("pcsx.supportpsx")
    set_kind("static")

    add_packages("fmt", "zlib")
    add_deps("pcsx.support")
    add_defines(
        "ACC_CONFIG_AUTO_NO_FUNCTIONS"
    )
    add_includedirs(
        path.join(support_root, "src"),
        path.join(support_root, "third_party"),
        path.join(support_root, "third_party", "ELFIO"),
        path.join(support_root, "third_party", "ucl"),
        path.join(support_root, "third_party", "ucl", "include")
    )

    add_files("*.c", "*.cc")

    add_files(
        path.join(support_root, "third_party", "ucl", "src", "alloc.c"),
        path.join(support_root, "third_party", "ucl", "src", "n2e_99.c")
    )
