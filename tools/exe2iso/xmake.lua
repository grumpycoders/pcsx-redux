local support_root = path.join(os.scriptdir(), "..", "..")

includes(path.join(support_root, "tools", "xmake"))

common_rules()

target("pcsx.exe2iso", common_tool)

rule("pcsx.exe2iso.iso", function()
    generic_conversion("pcsx.exe2iso", ".iso", "iso conversion")
end)
