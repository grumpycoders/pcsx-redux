--lualoader, R"EOF(--

-- seems this is the only way to escape these, as lua don't know how to map char '\a' to 'a'
local ESCAPE_MAP = {
    ['\a'] = '\\a', ['\b'] = '\\b', ['\f'] = '\\f', ['\n'] = '\\n', ['\r'] = '\\r',
    ['\t'] = '\\t', ['\v'] = '\\v', ['\\'] = '\\\\',
}

-- generic utilities
pprint._internals.tokenize_string = function(s)
    local t = {}
    for i = 1, #s do
        local c = s:sub(i, i)
        local b = c:byte()
        local e = ESCAPE_MAP[c]
        if (b >= 0x20 and b < 0x80) or e then
            local s = e or c
            t[i] = { char = s, len = #s }
        else
            t[i] = { char = string.format('\\x%02x', b), len = 4 }
        end
        if c == '"' then
            t.has_double_quote = true
        elseif c == "'" then
            t.has_single_quote = true
        end
    end
    return t
end
pprint._internals.tokenize_utf8_string = tokenize_string

local has_lpeg, lpeg = pcall(require, 'lpeg')

if has_lpeg then
    local function utf8_valid_char(c)
        return { char = c, len = 1 }
    end

    local function utf8_invalid_char(c)
        local b = c:byte()
        local e = ESCAPE_MAP[c]
        if (b >= 0x20 and b < 0x80) or e then
            local s = e or c
            return { char = s, len = #s }
        else
            return { char = string.format('\\x%02x', b), len = 4 }
        end
    end

    local cont = lpeg.R('\x80\xbf')
    local utf8_char =
        lpeg.R('\x20\x7f') +
        lpeg.R('\xc0\xdf') * cont +
        lpeg.R('\xe0\xef') * cont * cont +
        lpeg.R('\xf0\xf7') * cont * cont * cont

    local utf8_capture = (((utf8_char / utf8_valid_char) + (lpeg.P(1) / utf8_invalid_char)) ^ 0) * -1

    pprint._internals.tokenize_utf8_string = function(s)
        local dq = s:find('"')
        local sq = s:find("'")
        local t = table.pack(utf8_capture:match(s))
        t.has_double_quote = not not dq
        t.has_single_quote = not not sq
        return t
    end
end

local CACHE_TYPES = {
    ['table'] = true, ['function'] = true, ['thread'] = true,
    ['userdata'] = true, ['cdata'] = true,
}

-- cache would be populated to be like:
-- {
--     function = { `fun1` = 1, _cnt = 1 }, -- object id
--     table = { `table1` = 1, `table2` = 2, _cnt = 2 },
--     visited_tables = { `table1` = 7, `table2` = 8  }, -- visit count
-- }
-- use weakrefs to avoid accidentall adding refcount
pprint._internals.cache_apperance = function(obj, cache, option)
    if not cache.visited_tables then
        cache.visited_tables = setmetatable({}, {__mode = 'k'})
    end
    local t = type(obj)

    -- TODO can't test filter_function here as we don't have the ix and key,
    -- might cause different results?
    -- respect show_xxx and filter_function to be consistent with print results
    if (not pprint._internals.TYPES[t] and not option.show_table)
        or (pprint._internals.TYPES[t] and not option['show_'..t]) then
        return
    end

    if CACHE_TYPES[t] or pprint._internals.TYPES[t] == nil then
        if not cache[t] then
            cache[t] = setmetatable({}, {__mode = 'k'})
            cache[t]._cnt = 0
        end
        if not cache[t][obj] then
            cache[t]._cnt = cache[t]._cnt + 1
            cache[t][obj] = cache[t]._cnt
        end
    end
    if t == 'table' or pprint._internals.TYPES[t] == nil then
        if cache.visited_tables[obj] == false then
            -- already printed, no need to mark this and its children anymore
            return
        elseif cache.visited_tables[obj] == nil then
            cache.visited_tables[obj] = 1
        else
            -- visited already, increment and continue
            cache.visited_tables[obj] = cache.visited_tables[obj] + 1
            return
        end
        for k, v in pairs(obj) do
            pprint._internals.cache_apperance(k, cache, option)
            pprint._internals.cache_apperance(v, cache, option)
        end
        local mt = getmetatable(obj)
        if mt and option.show_metatable then
            pprint._internals.cache_apperance(mt, cache, option)
        end
    end
end

-- )EOF"
