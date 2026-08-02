local support_root = path.join(os.scriptdir(), "..", "..")

includes(path.join(support_root, "tools", "xmake"))

common_rules()

target("pcsx.ps1-packer", common_tool)

rule("pcsx.ps1-packer.psexe", function()
    generic_conversion("pcsx.ps1-packer", ".psexe", "psexe compression")
end)
