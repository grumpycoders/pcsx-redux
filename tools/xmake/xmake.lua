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

local function _values_list(target, name)
    local values = target:values(name)
    if values == nil then
        return {}
    end
    if type(values) == "string" then
        return { values }
    end
    return values
end

-- These helpers all report failures through a second return value instead of calling
-- raise(): xmake only rebinds the environment of the callback it is handed, so raise()
-- resolves to nil in any function defined at the top level of this file.
local function _single_value(target, name)
    local values = _values_list(target, name)
    if #values == 0 then
        return nil, nil
    end
    if #values > 1 then
        return nil, string.format("%s: expects a single value, got %d", name, #values)
    end
    return values[1], nil
end

local function _resolve_path(target, pathname)
    if path.is_absolute(pathname) then
        return path.absolute(pathname)
    end
    return path.absolute(path.join(target:scriptdir(), pathname))
end

local function _collect_globs(target, name)
    local entries = _values_list(target, name)
    local files = {}
    local seen = {}
    for _, entry in ipairs(entries) do
        local pattern = entry
        if not path.is_absolute(pattern) then
            pattern = path.join(target:scriptdir(), pattern)
        end

        local matches = os.files(pattern)
        if #matches == 0 and os.isfile(pattern) then
            matches = { pattern }
        end

        if #matches == 0 then
            return nil, string.format("%s: input '%s' did not match any file", name, entry)
        end

        for _, file in ipairs(matches) do
            local abs = path.absolute(file)
            if not seen[abs] then
                seen[abs] = true
                files[#files + 1] = abs
            end
        end
    end
    return files, nil
end

local function _json_string(value)
    local escaped = tostring(value)
    escaped = escaped:gsub("\\", "\\\\")
    escaped = escaped:gsub("\"", "\\\"")
    escaped = escaped:gsub("\n", "\\n")
    escaped = escaped:gsub("\r", "\\r")
    escaped = escaped:gsub("\t", "\\t")
    return "\"" .. escaped .. "\""
end

-- The authoring tool parses its configuration with ignore_comments turned on, while
-- xmake's own JSON parser rejects comments outright. Strip them, quotes aware, so that
-- a commented configuration still gets its file list tracked for incremental builds.
local function _json_strip_comments(text)
    local out = {}
    local i = 1
    local size = #text
    local in_string = false
    while i <= size do
        local c = text:sub(i, i)
        if in_string then
            if c == "\\" then
                out[#out + 1] = text:sub(i, i + 1)
                i = i + 2
            else
                if c == "\"" then
                    in_string = false
                end
                out[#out + 1] = c
                i = i + 1
            end
        elseif c == "\"" then
            in_string = true
            out[#out + 1] = c
            i = i + 1
        elseif c == "/" and text:sub(i + 1, i + 1) == "/" then
            local stop = text:find("\n", i, true)
            if not stop then break end
            i = stop
        elseif c == "/" and text:sub(i + 1, i + 1) == "*" then
            local stop = text:find("*/", i + 2, true)
            if not stop then break end
            out[#out + 1] = " "
            i = stop + 2
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    return table.concat(out)
end

local _pvd_keys = {
    "system_id", "volume_id", "volume_set_id", "publisher", "preparer",
    "application_id", "copyright", "abstract", "bibliographic",
}

local function _write_if_changed(io, os, pathname, data)
    if os.isfile(pathname) then
        local existing = io.open(pathname, "rb")
        if existing then
            local previous = existing:read("*all")
            existing:close()
            if previous == data then
                return true, nil
            end
        end
    end
    os.mkdir(path.directory(pathname))
    local f = io.open(pathname, "wb")
    if not f then
        return false, string.format("unable to write generated file '%s'", pathname)
    end
    f:write(data)
    f:close()
    return true, nil
end

-- Builds a disc image out of an authoring configuration. Two modes:
--   <prefix>.config <file>   imports a checked-in JSON configuration verbatim
--   <prefix>.files  <globs>  generates the JSON out of the psx binary dependency plus that file list
function authoring_image(tool, default_extension, conversion_name)
    local prefix = tool
    local rule_name = tool .. ".image"

    local function plan(target)
        local config, err = _single_value(target, prefix .. ".config")
        if err then return nil, err end
        local files = _values_list(target, prefix .. ".files")
        if config and #files > 0 then
            return nil, string.format(
                "%s: '%s' and '%s' are mutually exclusive; '%s' imports a configuration as-is while '%s' generates one - pick one",
                rule_name, prefix .. ".config", prefix .. ".files", prefix .. ".config", prefix .. ".files")
        end
        if not config and #files == 0 then
            return nil, string.format(
                "%s: no input files found; add values via %s (for example: add_values(\"%s\", \"assets/*.bin\")), or import an existing configuration with %s",
                rule_name, prefix .. ".files", prefix .. ".files", prefix .. ".config")
        end

        local result = {}
        result.license, err = _single_value(target, prefix .. ".license")
        if err then return nil, err end
        result.basedir, err = _single_value(target, prefix .. ".basedir")
        if err then return nil, err end
        if result.license then
            result.license = _resolve_path(target, result.license)
        end
        if result.basedir then
            result.basedir = _resolve_path(target, result.basedir)
        end

        if config then
            result.mode = "import"
            result.config = _resolve_path(target, config)
            if not os.isfile(result.config) then
                return nil, string.format("%s: configuration file '%s' does not exist", rule_name, result.config)
            end
        else
            result.mode = "generate"
            result.files, err = _collect_globs(target, prefix .. ".files")
            if err then return nil, err end
            result.config = path.join(target:autogendir(), "rules", "pcsx", "authoring",
                target:name() .. ".json")
        end
        return result, nil
    end

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
        local settings, err = plan(target)
        if not settings then
            raise(err)
        end
        if settings.mode == "generate" then
            local binary, binerr = get_binary_dep(target)
            if not binary then
                raise(rule_name .. " target error: " .. binerr)
            end
        end
    end)
    on_build(function(target)
        import("core.project.depend")
        import("core.base.json")

        os.mkdir(target:targetdir())
        local settings, err = plan(target)
        if not settings then
            raise(err)
        end
        local binary, binerr = get_binary_dep(target)
        if settings.mode == "generate" and not binary then
            raise(rule_name .. " target error: " .. binerr)
        end

        local inputs = {}
        if settings.mode == "generate" then
            local entries = {}
            for _, file in ipairs(settings.files) do
                entries[#entries + 1] = table.concat({
                    "        { \"path\": ", _json_string(file),
                    ", \"name\": ", _json_string(path.filename(file)), " }",
                }, "")
                inputs[#inputs + 1] = file
            end

            local pvd = {}
            for _, key in ipairs(_pvd_keys) do
                local value, pvderr = _single_value(target, prefix .. ".pvd." .. key)
                if pvderr then
                    raise(pvderr)
                end
                if value then
                    pvd[#pvd + 1] = "        " .. _json_string(key) .. ": " .. _json_string(value)
                end
            end

            -- targetfile() is relative to the project directory, and the authoring tool
            -- resolves every path in the configuration against its base directory, so it
            -- has to be made absolute before being written out.
            local executable = path.absolute(binary:targetfile(), os.projectdir())
            local lines = {
                "{",
                "    \"executable\": " .. _json_string(executable) .. ",",
            }
            if #pvd > 0 then
                lines[#lines + 1] = "    \"pvd\": {"
                lines[#lines + 1] = table.concat(pvd, ",\n")
                lines[#lines + 1] = "    },"
            end
            lines[#lines + 1] = "    \"files\": ["
            lines[#lines + 1] = table.concat(entries, ",\n")
            lines[#lines + 1] = "    ]"
            lines[#lines + 1] = "}"
            lines[#lines + 1] = ""
            local written, writeerr = _write_if_changed(io, os, settings.config, table.concat(lines, "\n"))
            if not written then
                raise(rule_name .. ": " .. writeerr)
            end
        else
            -- imported configurations name their own inputs; read them back so that
            -- incremental builds track every file the image is actually made of.
            local basedir = settings.basedir or path.directory(settings.config)
            local data = nil
            try {
                function()
                    data = json.decode(_json_strip_comments(io.readfile(settings.config)))
                end,
                catch {
                    function(errors)
                        data = nil
                        utils.warning(
                            "%s: unable to parse '%s' (%s); the image will only be rebuilt when the configuration itself, the executable or the license change",
                            rule_name, settings.config, tostring(errors))
                    end
                }
            }
            if type(data) == "table" then
                local listed = {}
                if type(data.executable) == "string" then
                    listed[#listed + 1] = data.executable
                end
                for _, entry in ipairs(data.files or {}) do
                    if type(entry) == "table" and type(entry.path) == "string" then
                        listed[#listed + 1] = entry.path
                    end
                end
                for _, entry in ipairs(listed) do
                    if not path.is_absolute(entry) then
                        entry = path.join(basedir, entry)
                    end
                    inputs[#inputs + 1] = path.absolute(entry)
                end
            end
        end

        inputs[#inputs + 1] = settings.config
        if binary then
            inputs[#inputs + 1] = path.absolute(binary:targetfile(), os.projectdir())
        end
        if settings.license then
            inputs[#inputs + 1] = settings.license
        end

        local output = target:targetfile()
        depend.on_changed(function()
            print(conversion_name .. " of %s to %s", settings.config, output)
            local tooldep = target:dep(tool)
            local argv = { settings.config, "-o", output }
            if settings.basedir then
                table.insert(argv, "-basedir")
                table.insert(argv, settings.basedir)
            end
            if settings.license then
                table.insert(argv, "-license")
                table.insert(argv, settings.license)
            end
            -- the tool truncates its output before it validates anything, so a failed run
            -- leaves a short but otherwise plausible looking image behind. Remove it.
            try {
                function()
                    os.vrunv(tooldep:targetfile(), argv)
                end,
                catch {
                    function(errors)
                        os.tryrm(output)
                        raise(errors)
                    end
                }
            }
        end, { files = inputs })
    end)
end
