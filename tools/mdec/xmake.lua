local support_root = path.join(os.scriptdir(), "..", "..")

includes(path.join(support_root, "tools", "xmake"))

common_rules()

target("pcsx.mdec", common_tool)
-- The decoder is GPLv2+ and lives in src/core, so it is compiled into this tool
-- directly rather than through the MIT supportpsx library, and without the rest
-- of core.
add_files(path.join(support_root, "src", "core", "mdec-decoder.cc"))
