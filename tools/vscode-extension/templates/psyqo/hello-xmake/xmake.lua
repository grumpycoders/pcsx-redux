includes("third_party/nugget/psyqo")

target("{{projectName}}", function()
    add_rules("psyqo.app", "ps-exe")
    add_files("*.cpp")
end)
