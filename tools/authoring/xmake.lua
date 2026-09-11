local support_root = path.join(os.scriptdir(), "..", "..")

includes(path.join(support_root, "tools", "xmake"))

common_rules()

target("pcsx.authoring", function ()
    common_tool()
    add_includedirs(path.join(support_root, "third_party", "ucl", "include"))
end)

rule("pcsx.authoring.iso", function()
    generic_conversion("pcsx.authoring", ".iso", "authoring")
end)
