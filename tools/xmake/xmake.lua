local support_root = path.join(os.scriptdir(), "..", "..")

function common_rules()
    add_rules("mode.debug", "mode.release")

    includes(
        path.join(support_root, "src", "support"),
        path.join(support_root, "src", "supportpsx")
    )

    add_requires("fmt", "zlib")
    set_languages("c++26")
end

function common_tool()
    set_kind("binary")

    add_packages("fmt", "zlib")
    add_deps("pcsx.support", "pcsx.supportpsx")
    add_includedirs(
        path.join(support_root, "src"),
        path.join(support_root, "third_party")
    )

    add_files("*.cc")
end

local function get_binary_dep(target)
    local deps = target:get("deps")
    if type(deps) == "string" then deps = { deps } end
    if not deps or #deps == 0 then
        return nil, "target must have at least one dependency"
    end
    local binary = nil
    for _, value in ipairs(deps) do
        if type(value) == "string" then
            local dep_target = target:dep(value)
            if not dep_target then
                return nil, "target dependency '" .. value .. "' does not exist"
            end
            if dep_target:get("kind") == "binary" and dep_target:get("plat") == "psx" and dep_target:get("arch") == "mipsel" then
                if binary then
                    return nil,
                        "target can only have one binary dependency, found '" ..
                        binary:name() .. "' and '" .. dep_target:name() .. "'"
                end
                if dep_target:get("plat") ~= "psx" then
                    return nil, "target dependency '" .. dep_target:name() .. "' must be a psx target"
                end
                binary = dep_target
            end
        else
            return nil, "target dependencies must be strings"
        end
    end
    if not binary then
        return nil, "target must have at least one binary dependency"
    end
    return binary
end

function generic_conversion(tool, default_extension, conversion_name)
    local tool_name = tool .. default_extension
    on_load(function(target)
        target:add("deps", tool, { inherit = false })
        target:set("kind", "binary")
        target:set("plat", "psx")
        target:set("arch", "mipsel")
        local extension = target:get("extension")
        if not extension then
            target:set("extension", default_extension)
        end
    end)
    before_config(function(target)
        local binary, err = get_binary_dep(target)
        if not binary then
            raise(tool_name .. " target error: " .. err)
        end
        target:set("basename", binary:basename())
    end)
    on_build(function(target)
        import("core.project.depend")

        os.mkdir(target:targetdir())
        local binary, err = get_binary_dep(target)
        if not binary then
            raise(tool_name .. " target error: " .. err)
        end
        local opts = {
            input = binary:targetfile(),
            output = target:targetfile(),
        }
        depend.on_changed(function()
            print(conversion_name .. " of %s to %s", opts.input, opts.output)
            local tooldep = target:dep(tool)
            os.vrunv(tooldep:targetfile(), { opts.input, "-o", opts.output })
        end, { files = opts.input })
    end)
end
