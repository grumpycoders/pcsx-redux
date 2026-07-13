local support_root = path.join(os.scriptdir(), "..", "..")

add_rules("mode.debug", "mode.release")

includes(
    path.join(support_root, "src", "support"),
    path.join(support_root, "src", "supportpsx")
)

add_requires("fmt", "zlib")
set_languages("c++26")

target("ps1-packer")
    set_kind("binary")

    add_packages("fmt", "zlib")
    add_deps("pcsx.support", "pcsx.supportpsx")
    add_includedirs(
        path.join(support_root, "src"),
        path.join(support_root, "third_party")
    )

    add_files("*.cc")

rule("ps1-packer.psexe")
    set_extensions(".elf")
    on_load(function(target)
        local extension = target:values("psx.extension")
        if extension == nil then
            extension = ".psexe"
        end
        local targetdir = target:targetdir()
        local targetname = target:basename()
        local outfile = path.join(targetdir, targetname .. extension)
        target:add("deps", "ps1-packer", {inherit = false})
        target:add("values", "ps1-packer.psexe.postlink.outfile", outfile)
        target:add("values", "psexe", false)
    end)
    after_link(function(target)
        local ps1packer = target:dep("ps1-packer")
        local outfile = target:values("ps1-packer.psexe.postlink.outfile")
        os.run("%s %s -o %s", ps1packer:targetfile(), target:targetfile(), outfile)
    end)
    on_clean(function(target)
        local outfile = target:values("ps1-packer.psexe.postlink.outfile")
        os.tryrm(outfile)
    end)
