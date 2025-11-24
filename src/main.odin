package main

import "core:fmt"
import "core:flags"
import "core:strings"
import os "core:os/os2"
import lua "luajit"
import "luv"

USAGE :: "run FILENAME"

entry_point :: proc() -> int {
    if len(os.args) != 3 || os.args[1] != "run" {
        fmt.eprintf("usage: %s %s\n", os.args[0], USAGE);
        return 1
    }
    filename := strings.unsafe_string_to_cstring(os.args[2])

    L := lua.L_newstate()
    defer lua.close(L)

    lua.L_openlibs(L)

    // define lash global table
    lua.newtable(L);
    lua.setglobal(L, "lash");

    // add runtime to path
    // package.path = "src/runtime/?.lua;" .. package.path
    lua.getglobal(L, "package")                           // [package]
    lua.getfield(L, -1, "path")                           // [package, path]
    old := lua.tostring(L, -1)
    lua.pop(L, 1)                                         // [package]
    lua.pushfstring(L, "%s;%s", old, "src/runtime/?.lua") // [package, new_path]
    lua.setfield(L, -2, "path")                           // [package]
    lua.pop(L, 1)                                         // []

    // lash.uv
    lua.getglobal(L, "lash");   // [lash]
    luv.open_luv(L);            // pushes uv. [lash, uv]
    lua.pushvalue(L, -1);       // [lash, uv, uv]
    lua.setfield(L, -3, "uv");  // [lash, uv]

    // package.loaded.uv
    lua.getglobal(L, "package");   // [lash, uv, package]
    lua.getfield(L, -1, "loaded"); // [lash, uv, package, loaded]
    lua.pushvalue(L, -3);          // [lash, uv, package, loaded, uv]
    lua.setfield(L, -2, "luv");    // [lash, uv, package, loaded]
    lua.pop(L, 3);                 // [lash]

    // evaluate init.lua
    status := lua.L_dofile(L, "src/runtime/init.lua");
    if status != .OK {
        fmt.eprintf("%s\n", lua.tostring(L, -1)); // show error
        return 1
    }

    // evaluate file
    status = lua.L_dofile(L, filename)
    if status != .OK {
        fmt.eprintf("%s\n", lua.tostring(L, -1)); // show error
        return 1
    }

    return 0
}

// os.exit() ignores defer
main :: proc() {
    os.exit(entry_point())
}
