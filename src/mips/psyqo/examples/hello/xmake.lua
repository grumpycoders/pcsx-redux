local psyqo = path.join(os.scriptdir(), "..", "..")

includes(psyqo)

target("hello", function()
    add_rules("psyqo.app")
    add_files("*.cpp")
end)
