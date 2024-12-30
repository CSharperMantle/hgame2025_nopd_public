set_languages("gnu23")
set_allowedplats("linux")
set_plat("linux")
set_allowedarchs("x86_64")
set_arch("x86-64")

if is_mode("debug") then
    add_defines("CSMANTLE")
    add_cflags("-Og")
    set_symbols("debug")
elseif is_mode("release") then
    add_defines("CSMANTLE", "CHALL")
    set_optimize("fast")
    set_symbols("hidden")
    set_strip("all")
elseif is_mode("challenge") then
    add_defines("CHALL")
    set_optimize("fast")
    set_symbols("hidden")
    set_strip("all")
end

add_defines("_GNU_SOURCE=1")
set_warnings("all", "extra", "error")
add_cflags("-flto")

add_includedirs("include")

target("nop_host")
    set_kind("binary")
    set_basename("launcher")
    add_files("src/host/*.c")

target("nop_guest")
    set_kind("binary")
    set_basename("game")
    set_strip("debug")
    add_files("src/guest/*.c")
