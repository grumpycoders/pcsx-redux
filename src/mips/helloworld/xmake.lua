local root = path.join(os.scriptdir(), "..", "..", "..")
local mips = path.join(os.scriptdir(), "..")

set_allowedmodes("debug", "dev", "release")
includes(path.join(root, "tools", "exe2iso"))
includes(path.join(root, "tools", "ps1-packer"))
includes(mips)

target("helloworld", function()
    set_kind("binary")
    add_rules("nugget")
    add_files("main/**.c")
end)

target("helloworld.ps-exe", function()
    add_deps("helloworld")
    add_rules("pcsx.ps1-packer.psexe")
end)

target("helloworld.iso", function()
    add_deps("helloworld.ps-exe")
    add_rules("pcsx.exe2iso.iso")
end)
