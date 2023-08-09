--lualoader, R"EOF(--

pprint = { VERSION = '0.1' }

local depth = 1

pprint._internals = {}

pprint.defaults = {
    -- If set to number N, then limit table recursion to N deep.
    depth_limit = false,
    -- type display trigger, hide not useful datatypes by default
    -- custom types are treated as table
    show_nil = true,
    show_boolean = true,
    show_number = true,
    show_string = true,
    show_table = true,
    show_function = false,
    show_thread = false,
    show_userdata = false,
    show_cdata = false,
    -- additional display trigger
    show_metatable = false,     -- show metatable
    show_all = false,           -- override other show settings and show everything
    use_tostring = false,       -- use __tostring to print table if available
    filter_function = nil,      -- called like callback(value[,key, parent]), return truty value to hide
    object_cache = 'local',     -- cache blob and table to give it a id, 'local' cache per print, 'global' cache
                                -- per process, falsy value to disable (might cause infinite loop)
    -- format settings
    indent_size = 2,            -- indent for each nested table level
    level_width = 80,           -- max width per indent level
    wrap_string = true,         -- wrap string when it's longer than level_width
    wrap_array = false,         -- wrap every array elements
    string_is_utf8 = true,      -- treat string as utf8, and count utf8 char when wrapping, if possible
    sort_keys = true,           -- sort table keys
}

pprint._internals.TYPES = {
    ['nil'] = 1, ['boolean'] = 2, ['number'] = 3, ['string'] = 4, 
    ['table'] = 5, ['function'] = 6, ['thread'] = 7, ['userdata'] = 8,
    ['cdata'] = 9,
}

local function is_plain_key(key)
    return type(key) == 'string' and key:match('^[%a_][%a%d_]*$')
end

-- makes 'foo2' < 'foo100000'. string.sub makes substring anyway, no need to use index based method
local function str_natural_cmp(lhs, rhs)
    while #lhs > 0 and #rhs > 0 do
        local lmid, lend = lhs:find('%d+')
        local rmid, rend = rhs:find('%d+')
        if not (lmid and rmid) then return lhs < rhs end

        local lsub = lhs:sub(1, lmid-1)
        local rsub = rhs:sub(1, rmid-1)
        if lsub ~= rsub then
            return lsub < rsub
        end
        
        local lnum = tonumber(lhs:sub(lmid, lend))
        local rnum = tonumber(rhs:sub(rmid, rend))
        if lnum ~= rnum then
            return lnum < rnum
        end

        lhs = lhs:sub(lend+1)
        rhs = rhs:sub(rend+1)
    end
    return lhs < rhs
end

local function cmp(lhs, rhs)
    local tleft = type(lhs)
    local tright = type(rhs)
    if tleft == 'number' and tright == 'number' then return lhs < rhs end
    if tleft == 'string' and tright == 'string' then return str_natural_cmp(lhs, rhs) end
    if tleft == tright then return str_natural_cmp(tostring(lhs), tostring(rhs)) end

    -- allow custom types
    local oleft = pprint._internals.TYPES[tleft] or 10
    local oright = pprint._internals.TYPES[tright] or 10
    return oleft < oright
end

-- setup option with default
local function make_option(option)
    if option == nil then
        option = {}
    end
    for k, v in pairs(pprint.defaults) do
        if option[k] == nil then
            option[k] = v
        end
        if option.show_all then
            for t, _ in pairs(pprint._internals.TYPES) do
                option['show_'..t] = true
            end
            option.show_metatable = true
        end
    end
    return option
end

-- override defaults and take effects for all following calls
function pprint.setup(option)
    pprint.defaults = make_option(option)
end

-- format lua object into a string
function pprint.pformat(obj, option, printer)
    option = make_option(option)
    local buf = {}
    local function default_printer(s)
        table.insert(buf, s)
    end
    printer = printer or default_printer

    local cache
    if option.object_cache == 'global' then
        -- steal the cache into a local var so it's not visible from _G or anywhere
        -- still can't avoid user explicitly referentce pprint._cache but it shouldn't happen anyway
        cache = pprint._cache or {}
        pprint._cache = nil
    elseif option.object_cache == 'local' then
        cache = {}
    end

    local last = '' -- used for look back and remove trailing comma
    local status = {
        indent = '', -- current indent
        len = 0,     -- current line length
        printed_something = false, -- used to remove leading new lines
    }

    local wrapped_printer = function(s)
        status.printed_something = true
        printer(last)
        last = s
    end

    local function _indent(d)
        status.indent = string.rep(' ', d + #(status.indent))
    end

    local function _n(d)
        if not status.printed_something then return end
        wrapped_printer('\n')
        wrapped_printer(status.indent)
        if d then
            _indent(d)
        end
        status.len = 0
        return true -- used to close bracket correctly
    end

    local function _p(s, nowrap)
        status.len = status.len + #s
        if not nowrap and status.len > option.level_width then
            _n()
            wrapped_printer(s)
            status.len = #s
        else
            wrapped_printer(s)
        end
    end

    local formatter = {}
    local function format(v)
        local f = formatter[type(v)]
        f = f or formatter.table -- allow patched type()
        if option.filter_function and option.filter_function(v, nil, nil) then
            return ''
        else
            return f(v)
        end
    end

    local function tostring_formatter(v)
        return tostring(v)
    end

    local function number_formatter(n)
        return n == math.huge and '[[math.huge]]' or tostring(n)
    end

    local function nop_formatter(v)
        return ''
    end

    local function make_fixed_formatter(t, has_cache)
        if has_cache then
            return function (v)
                return string.format('[[%s %d]]', t, cache[t][v])
            end
        else
            return function (v)
                return '[['..t..']]'
            end
        end
    end

    local function string_formatter(s, force_long_quote)
        local tokens = option.string_is_utf8 and pprint._internals.tokenize_utf8_string(s) or pprint._internals.tokenize_string(s)
        local string_len = 0
        local escape_quotes = tokens.has_double_quote and tokens.has_single_quote
        for _, token in ipairs(tokens) do
            if escape_quotes and token.char == '"' then
                string_len = string_len + 2
            else
                string_len = string_len + token.len
            end
        end
        local quote_len = 2
        local long_quote_dashes = 0
        local function compute_long_quote_dashes()
            local keep_looking = true
            while keep_looking do
                if s:find('%]' .. string.rep('=', long_quote_dashes) .. '%]') then
                    long_quote_dashes = long_quote_dashes + 1
                else
                    keep_looking = false
                end
            end
        end
        if force_long_quote then
            compute_long_quote_dashes()
            quote_len = 2 + long_quote_dashes
        end
        if quote_len + string_len + status.len > option.level_width then
            _n()
            -- only wrap string when is longer than level_width
            if option.wrap_string and string_len + quote_len > option.level_width then
                if not force_long_quote then
                    compute_long_quote_dashes()
                    quote_len = 2 + long_quote_dashes
                end
                -- keep the quotes together
                local dashes = string.rep('=', long_quote_dashes)
                _p('[' .. dashes .. '[', true)
                local status_len = status.len
                local line_len = 0
                local line = ''
                for _, token in ipairs(tokens) do
                    if line_len + token.len + status_len > option.level_width then
                        _n()
                        _p(line, true)
                        line_len = token.len
                        line = token.char
                    else
                        line_len = line_len + token.len
                        line = line .. token.char
                    end
                end

                return line .. ']' .. dashes .. ']'
            end
        end

        if tokens.has_double_quote and tokens.has_single_quote and not force_long_quote then
            for i, token in ipairs(tokens) do
                if token.char == '"' then
                    tokens[i].char = '\\"'
                end
            end
        end
        local flat_table = {}
        for _, token in ipairs(tokens) do
            table.insert(flat_table, token.char)
        end
        local concat = table.concat(flat_table)

        if force_long_quote then
            local dashes = string.rep('=', long_quote_dashes)
            return '[' .. dashes .. '[' .. concat .. ']' .. dashes .. ']'
        elseif tokens.has_single_quote then
            -- use double quote
            return '"' .. concat .. '"'
        else
            -- use single quote
            return "'" .. concat .. "'"
        end
    end

    local function table_formatter(t)
        if option.use_tostring then
            local mt = getmetatable(t)
            if mt and mt.__tostring then
                return string_formatter(tostring(t), true)
            end
        end

        local print_header_ix = nil
        local ttype = type(t)
        if option.object_cache then
            local cache_state = cache.visited_tables[t]
            local tix = cache[ttype][t]
            -- FIXME should really handle `cache_state == nil`
            -- as user might add things through filter_function
            if cache_state == false then
                -- already printed, just print the the number
                return string_formatter(string.format('%s %d', ttype, tix), true)
            elseif cache_state > 1 then
                -- appeared more than once, print table header with number
                print_header_ix = tix
                cache.visited_tables[t] = false
            else
                -- appeared exactly once, print like a normal table
            end
        end

        local limit = tonumber(option.depth_limit)
        if limit and depth > limit then
           if print_header_ix then
              return string.format('[[%s %d]]...', ttype, print_header_ix)
           end
           return string_formatter(tostring(t), true)
        end

        local tlen = #t
        local wrapped = false
        _p('{')
        _indent(option.indent_size)
        _p(string.rep(' ', option.indent_size - 1))
        if print_header_ix then
            _p(string.format('--[[%s %d]] ', ttype, print_header_ix))
        end
        for ix = 1,tlen do
            local v = t[ix]
            if formatter[type(v)] == nop_formatter or 
               (option.filter_function and option.filter_function(v, ix, t)) then
               -- pass
            else
                if option.wrap_array then
                    wrapped = _n()
                end
                depth = depth+1
                _p(format(v)..', ')
                depth = depth-1
            end
        end

        -- hashmap part of the table, in contrast to array part
        local function is_hash_key(k)
            if type(k) ~= 'number' then
                return true
            end

            local numkey = math.floor(tonumber(k))
            if numkey ~= k or numkey > tlen or numkey <= 0 then
                return true
            end
        end

        local function print_kv(k, v, t)
            -- can't use option.show_x as obj may contain custom type
            if formatter[type(v)] == nop_formatter or
               formatter[type(k)] == nop_formatter or 
               (option.filter_function and option.filter_function(v, k, t)) then
                return
            end
            wrapped = _n()
            if is_plain_key(k) then
                _p(k, true)
            else
                _p('[')
                -- [[]] type string in key is illegal, needs to add spaces inbetween
                local k = format(k)
                if string.match(k, '%[%[') then
                    _p(' '..k..' ', true)
                else
                    _p(k, true)
                end
                _p(']')
            end
            _p(' = ', true)
            depth = depth+1
            _p(format(v), true)
            depth = depth-1
            _p(',', true)
        end

        if option.sort_keys then
            local keys = {}
            for k, _ in pairs(t) do
                if is_hash_key(k) then
                    table.insert(keys, k)
                end
            end
            table.sort(keys, cmp)
            for _, k in ipairs(keys) do
                print_kv(k, t[k], t)
            end
        else
            for k, v in pairs(t) do
                if is_hash_key(k) then
                    print_kv(k, v, t)
                end
            end
        end

        if option.show_metatable then
            local mt = getmetatable(t)
            if mt then
                print_kv('__metatable', mt, t)
            end
        end

        _indent(-option.indent_size)
        -- make { } into {}
        last = string.gsub(last, '^ +$', '')
        -- peek last to remove trailing comma
        last = string.gsub(last, ',%s*$', ' ')
        if wrapped then
            _n()
        end
        _p('}')

        return ''
    end

    -- set formatters
    formatter['nil'] = option.show_nil and tostring_formatter or nop_formatter
    formatter['boolean'] = option.show_boolean and tostring_formatter or nop_formatter
    formatter['number'] = option.show_number and number_formatter or nop_formatter -- need to handle math.huge
    formatter['function'] = option.show_function and make_fixed_formatter('function', option.object_cache) or nop_formatter
    formatter['thread'] = option.show_thread and make_fixed_formatter('thread', option.object_cache) or nop_formatter
    formatter['userdata'] = option.show_userdata and make_fixed_formatter('userdata', option.object_cache) or nop_formatter
    formatter['string'] = option.show_string and string_formatter or nop_formatter
    formatter['table'] = option.show_table and table_formatter or nop_formatter
    formatter['cdata'] = option.show_cdata and make_fixed_formatter('cdata', option.object_cache) or nop_formatter

    if option.object_cache then
        -- needs to visit the table before start printing
        pprint._internals.cache_apperance(obj, cache, option)
    end

    _p(format(obj))
    printer(last) -- close the buffered one

    -- put cache back if global
    if option.object_cache == 'global' then
        pprint._cache = cache
    end

    return table.concat(buf)
end

-- pprint all the arguments
function pprint.pprint( ... )
    local args = {...}
    local accum = ''
    -- select will get an accurate count of array len, counting trailing nils
    local len = select('#', ...)
    for ix = 1,len do
        pprint.pformat(args[ix], nil, function(str)
            if str == '\n' then
                print(accum)
                accum = ''
            else
                accum = accum .. str
            end
        end)
        print(accum)
        accum = ''
    end
end

setmetatable(pprint, {
    __call = function (_, ...)
        pprint.pprint(...)
    end
})

-- )EOF"
