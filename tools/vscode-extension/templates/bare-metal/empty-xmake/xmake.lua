includes("third_party/nugget")

target("{{projectName}}", function()
    set_kind("binary")
    add_rules("nugget", "ps-exe")
    add_files("*.c")
end)
