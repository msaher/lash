package main

import "core:fmt"
import "core:strings"
import os "core:os/os2"
import "core:bufio"
import lua "luajit"
import "luv"
import "core:c"
import "core:sys/posix"
import "base:runtime"

USAGE :: "run FILENAME"

lash_input :: proc "c" (L: ^lua.State) -> c.int {
    num_args := lua.gettop(L)
    if num_args < 1 {
        return lua.L_error(L, "Expected at least 1 argument")
    }

    has_prompt := lua.isstring(L, 1)
    if !lua.isnil(L, 1) && !has_prompt {
        return lua.L_error(L, "prompt: expected string, got %s", lua.L_typename(L, 1))
    }

    context = runtime.default_context()
    if has_prompt {
        prompt := lua.tostring(L, 1)
        fmt.print(prompt)
    }

    want_echo: b32 = true
    // opts
    if num_args > 1 && !lua.isnil(L, 2) {
        lua.getfield(L, 2, "echo")
        if !lua.isnil(L, -1) {
            if !lua.isboolean(L, -1) {
                return lua.L_error(L, "echo: expected boolean, got %s", lua.L_typename(L, -1))
            }
            want_echo = lua.toboolean(L, -1)
        }
        lua.pop(L, 1)
    }

    stdin_fd := posix.FD(os.fd(os.stdin))

    // TODO: support for windows
    term: posix.termios
    if !want_echo {
        // do we handle errors? if not tty
        posix.tcgetattr(stdin_fd, &term)
        term.c_lflag -= { .ECHO }
        posix.tcsetattr(stdin_fd, .TCSANOW, &term)
    }

    stdin_reader := os.to_reader(os.stdin)
    stdin_scanner: bufio.Scanner
    bufio.scanner_init(&stdin_scanner, stdin_reader, context.temp_allocator)

    if !bufio.scan(&stdin_scanner) {
        err := bufio.scanner_error(&stdin_scanner)
        bufio.scanner_destroy(&stdin_scanner)
        if err == nil { // nil means EOF
            return lua.L_error(L, "EOF when reading a line")
        }
        msg := fmt.caprint(err)
        lua_push_errmsg(L, msg)
        delete(msg)
        return lua.error(L)
    }

    line := bufio.scanner_text(&stdin_scanner)
    bufio.scanner_destroy(&stdin_scanner)
    lua.pushlstring(L, strings.unsafe_string_to_cstring(line), len(line))

    // turn back echo after we turn it off
    if !want_echo {
        term.c_lflag += { .ECHO }
        posix.tcsetattr(stdin_fd, .TCSANOW, &term)
        fmt.println()
    }

    return 1
}

lash_get_metatable :: proc "c" (L: ^lua.State) -> c.int {
    mt_name := lua.tostring(L, 1)
    lua.L_getmetatable(L, mt_name)
    return 1
}

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

    // define metatables
    define_cmd_metatable(L)
    define_ssh_cmd_metatable(L)
    define_ssh_session_metatable(L)

    lua.pushcfunction(L, lash_ssh_connect)
    lua.setfield(L, 1, "_ssh_connect")

    lua.pushcfunction(L, lash_get_metatable)
    lua.setfield(L, 1, "_get_metatable")

    // @param prompt string?
    // @param opts? {blind?: boolean}
    // @return string?
    // input()
    lua.pushcfunction(L, lash_input)
    lua.setfield(L, 1, "input")

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
