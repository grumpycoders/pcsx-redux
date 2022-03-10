Taken and adapted from https://github.com/jagt/pprint.lua.

# pprint.lua

__easy lua pretty printing, customizable and public domain!__

[![Actions Status](https://github.com/jagt/pprint.lua/workflows/test/badge.svg)](https://github.com/jagt/pprint.lua/actions)

pprint.lua is a friendly reimplementation of [inspect.lua][1]. `pprint(whatever)` in which `whatever` is anything you can find in Lua. It would dump it into a meaningful representation. Notably features:

* Limited customization through setting options.
* Sensible defaults, like _not_ printing functions, userdatas, wrapping long lines etc.
* Printed results can be evaled (can't guaranteed to be identical as the original value).
* Tested on Lua 5.1, 5.2, 5.3, 5.4 and Luajit 2.0.2.
* Released into the Public Domain, for whatever reason.

Example:

```lua
local pprint = require('pprint')
pprint(_G)
-- dumped _G to standard output:
-- { --[[table 1]]
--   _G = [[table 1]],
--   _VERSION = 'Lua 5.1',
--   arg = {},
--   coroutine = { --[[table 11]] },
--   debug = { --[[table 6]] },
--   io = { --[[table 7]] },
--   math = { --[[table 10]]
--     huge = 1.#INF,
--     pi = 3.1415926535898
--   },
--   os = { --[[table 8]] },
--   package = { --[[table 3]]
--   ...
```

## Usage

Grab [`pprint.lua`](https://raw.github.com/jagt/pprint.lua/master/pprint.lua) and drop it into your project. Then just require and start printing:

    local pprint = require('pprint')
    pprint({ foo = 'bar' })

If you're on LuaRocks then just get [`inspect.lua`][1] instead. It's been around longer and more stable.

pprint.lua exposes `pprint` table with two other functions:

* `pprint(...)` : pretty print arguments, each argument starting on a new line.
* `pprint.pformat(obj[, option[, printer]])` : return the string representation of `obj`. Provide `option` to override global settings during this invoke. `printer` will be called repeatedly with string segments from the output. For example `pprint` uses `io.write` as printer.
* `pprint.setup(option)` : setup global options, affecting all following calls.
* `pprint.defaults` : default settings. `pprint(pprint.defaults)` to see what's in it.

## Options

You can configure `pprint` behaviors by using `pprint.setup` or pass a table into `pformat`:

```lua
pprint.setup {
    show_all = true,
    wrap_array = true,
}
print(pprint.format(pprint.defaults, {sort_keys = false}))
```

Available options are:

* __show_{type}__ : skip values of given `type` when set to false. This includes the type of value as key, value or array element of a table. Defaults to show only `nil`, `boolean`, `number`, `string`. In some projects `type()` might returns non standard types. pprint.lua treats all these as `table`, which in most cases should be reasonable.
* __show_metatable__ : whether show metatable. Defaults to `false`.
* __show_all__ : show everything when set to `true`. It overrides all other `show` options. Defaults to `false`.
* __use_tostring__ : show table by using `__tostring` when available. Defaults to `false`.
* __filter_function__ : provide a function and it would be called as `func(v, [k, t])`. `v` is the value. `k` is key or index while `t` is the parent, which isn't always available. Return truthy values to skip showing this value. Here's an example for hiding empty tables:

    ```lua
    pprint.setup{filter_function = function(v, k)
        return type(v) == 'table' and not next(v)
    end}
    ```

* __object_cache__ : table might contain cyclic references and simply print all values would cause an infinite loop. __object_cache__ defaults to `local` so pprint would refer previously seen table with a short name. Set to `global` will cause the cache be kept between pprint invokes. Set to `false` to disable, which might cause infinite loop.

    ```lua
    empty = {}
    d = {a=empty, b=empty, c=empty}
    pprint(d)
    -- {
    --   a = { --[[table 2]] },
    --   b = [[table 2]],
    --   c = [[table 2]]
    -- }
    ```

* __indent_size__ : indent size for each nested table. Defaults to `2`.
* __level_width__ : max width per indent level. Defaults to `80`.
* __wrap_string__ : wrap strings longer than __level_width__. Defaults to `true`.
    
    ```lua
    pprint.setup({level_width = 12, wrap_string = true})
    pprint('these are my twisted words.')
    -- [[these are
    -- my twisted w
    -- ords.]]
    ```

* __wrap_array__ : whether print each each array element on newline. Defaults to `false`.
* __sort_keys__ : natural-sort table keys for easier reading. Defaults to `true`.

## Bugs

Currently pprint.lua should be usable, meaning there's no obvious issues. If you've found something is wrong please do open an issue.

1. There aren't enough tests yet.
1. Combination of some settings might cause visual artifacts in the output.
1. eval `pformat` results might not always work, as string escaping isn't perfect atm.

## TODOs

* verbose name tag printing, `ie --[[table io]]`
* show_custom type, `option.show_foo = function(v) ... end`

## License

Public Domain

[1]:https://github.com/kikito/inspect.lua "inspect.lua"

