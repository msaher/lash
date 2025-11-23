package main

import "core:fmt"
import "core:flags"
import "core:strings"
import os "core:os/os2"
import lua "luajit"

USAGE :: "run FILENAME"

main :: proc() {
    if len(os.args) != 3 || os.args[1] != "run" {
        fmt.eprintf("usage: %s %s\n", os.args[0], USAGE);
        os.exit(1)
    }
    filename := strings.unsafe_string_to_cstring(os.args[2])

    L := lua.L_newstate()
    defer lua.close(L)

    lua.L_openlibs(L)

    status := lua.L_dofile(L, filename)
    if status != .OK {
        fmt.eprintf("%s\n", lua.tostring(L, -1)); // show error
        os.exit(1)
    }

    fmt.println(lua.Status.OK)
}
