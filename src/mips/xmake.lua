local root = path.join(os.scriptdir(), "..", "..")
local mips = path.join(os.scriptdir())

includes(path.join(root, "third_party", "xmake-psx"))

rule("nugget", function()
    add_deps("psx")
    on_load(function(target)
        target:add("includedirs", mips)
        target:add("values", "psx.no_crt", true)
        target:add("values", "psx.no_ldscript", true)
        target:add("values", "psx.nogp", true)
    end)
    before_config(function (target)
        if target:get("kind") == "binary" then
            if target:values("c++") then
                target:add("files", path.join(mips, "common", "crt0", "crt0cxx.s"))
                target:add("files", path.join(mips, "common", "crt0", "cxxglue.c"))
            else
                target:add("files", path.join(mips, "common", "crt0", "crt0.s"))
            end
            target:add("files", path.join(mips, "common", "crt0", "memory-c.c"))
            target:add("files", path.join(mips, "common", "crt0", "memory-s.s"))
            target:add("files", path.join(mips, "common", "syscalls", "printf.s"))
            target:add("files", path.join(mips, "xmake.ld"))
            target:add("files", path.join(mips, "nooverlay.ld"))
        end
    end)
end)
