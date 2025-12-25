package main

import lua "luajit"
import "base:runtime"
import "core:c"
import "core:fmt"
import "core:sys/posix"
import "core:io"
import os "core:os/os2"
import "core:strings"


// metatable name for lua files
LUAFILE_HANDLE :: "FILE*"

lua_push_errmsg :: proc "contextless" (L: ^lua.State, msg: cstring) {
    lua.L_where(L, 1)
    lua.pushstring(L, msg)
    lua.concat(L, 2)
}

lua_error_from_enum :: proc "contextless" (L: ^lua.State, err: any) -> c.int {
    lua_push_error_from_enum(L, err)
    return lua.error(L)
}

lua_push_error_from_enum :: proc "contextless" (L: ^lua.State, err: any) {
    context = runtime.default_context()
    msg := fmt.caprint(err)
    lua_push_errmsg(L, msg)
    delete(msg)
}

// check luajit's string.buffer
// lua.testudata is not useful because it seems the string.buffer metatable is not in the registery
// as a hacky workaround we check for the existence of some methods until we figure how to properly do it
luajit_is_buffer :: proc "contextless" (L: ^lua.State, idx: lua.Index) -> bool {
    methods := []cstring{"put", "tostring", "ref"}
    for method in methods {
        lua.getfield(L, idx, method)
        defer lua.pop(L, 1)
        if lua.type(L, -1) != .FUNCTION {
            return false
        }
    }
    return true
}

lua_check :: proc "contextless" (L: ^lua.State, idx: lua.Index, name: cstring, allowed_types: bit_set[lua.Type], msg: cstring) -> lua.Type {
    lua.getfield(L, idx, name)
    type := lua.type(L, -1)
    if .NIL in allowed_types && type == .NIL {
        return .NIL
    }

    if type not_in allowed_types {
        type_name := lua.L_typename(L, -1)
        lua.L_error(L, "%s: %s, got %s", name, msg, type_name)
    }
    return type
}

lua_check_with_udata :: proc "contextless" (L: ^lua.State, idx: lua.Index, name: cstring, allowed_types: bit_set[lua.Type], msg: cstring, metatables := []cstring{}) -> (lua.Type, cstring) {
    type := lua_check(L, idx, name, allowed_types | {.USERDATA}, msg)
    if type != .USERDATA {
        return type, ""
    }

    match_metatable :: proc "contextless" (L: ^lua.State, idx: lua.Index, metatables: []cstring) -> (cstring, bool) {
        for metatable in metatables {
            if metatable == "buffer" && luajit_is_buffer(L, -1) {
                return metatable, true
            } else if lua.L_testudata(L, -1, metatable) != nil {
                return metatable, true
            }
        }
        return "", false
    }

    metatable, found := match_metatable(L, idx, metatables)
    if !found {
        type_name := lua.L_typename(L, -1)
        lua.L_error(L, "%s: %s, got %s", name, msg, type_name)
    }
    return type, metatable

}

// [target, table, field]
lua_check_and_set :: proc "contextless" (L: ^lua.State, name: cstring, allowed_types: bit_set[lua.Type], msg: cstring, metatables := []cstring{}) {
    type, _ := lua_check_with_udata(L, -1, name, allowed_types, msg, metatables)
    if type != .NIL {
        lua.setfield(L, -3, name)
    } else {
        lua.pop(L, 1)
    }
}

lua_tostring_pop :: proc "contextless" (L: ^lua.State) -> cstring {
    s := lua.tostring(L, -1)
    lua.pop(L, 1)
    return s
}

lua_file_to_odin_file :: proc (L: ^lua.State, idx: lua.Index) -> (file: ^os.File, mode: c.int, err: posix.Errno) {
    cfile_ptr_ptr := cast(^^c.FILE) lua.touserdata(L, idx)
    fd := posix.fileno(cfile_ptr_ptr^)

    flags := posix.fcntl(fd, .GETFL)
    if flags == -1 {
        err = posix.get_errno()
        return
    }
    mode = flags & c.int(posix.O_ACCMODE)
    file = os.new_file(uintptr(fd), "")
    return
}

lua_file_to_stream :: proc (L: ^lua.State, idx: lua.Index) -> (stream: io.Stream, mode: c.int, err: posix.Errno) {
    file: ^os.File
    file, mode, err = lua_file_to_odin_file(L,  idx)
    stream = os.to_stream(file)
    return
}

Lua_Stream_Data :: struct {
    L: ^lua.State,
    ref: c.int,
}

Buffer_Writer :: Lua_Stream_Data

// can also be used as a os.File
buffer_writer_stream_proc :: proc(stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (n: i64, err: io.Error) {
    #partial switch mode {
    case .Query:
        return io.query_utility({.Write})
    case .Write:
        buffer_writer := cast(^Buffer_Writer) stream_data
        L := buffer_writer.L
        ref := buffer_writer.ref

        lua.rawgeti(L, lua.REGISTRYINDEX, lua.Integer(ref)) // [buf]
        lua.getfield(L, -1, "put") //  [buf, put]
        lua.pushvalue(L, -2) // [buf, put, buf]
        lua.pushlstring(L, cstring(raw_data(p)), len(p)) // [buf, put, buf, string]
        lua.call(L, 2, 0) // [buf, put]
        lua.pop(L, 1) // []

        return i64(len(p)), nil
    case:
        return 0, .Empty
    }
}

buffer_writer_to_stream :: proc(bw: ^Buffer_Writer) -> io.Stream {
    return io.Stream {
        data = bw,
        procedure = buffer_writer_stream_proc,
    }
}

buffer_writer_file_proc :: proc(
    stream_data: rawptr,
    mode:        os.File_Stream_Mode,
    p:           []byte,
    offset:      i64,
    whence:      io.Seek_From,
    allocator:   runtime.Allocator,
) -> (n: i64, err: os.Error) {
    if mode == .Fstat {
        return 0, .Empty
    }
    stream_mode := transmute(io.Stream_Mode)mode

    return buffer_writer_stream_proc(stream_data, stream_mode, p, offset, whence)
}

lua_stream_data_unref :: proc "contextless" (data: ^Lua_Stream_Data) {
    if data.L != nil {
        lua.L_unref(data.L, lua.REGISTRYINDEX, data.ref)
    }
}

// converts buffer or file to io.Writer
lua_stdio_to_writer :: proc(L: ^lua.State, idx: lua.Index, data: ^Lua_Stream_Data, metatable: cstring) -> (writer: io.Writer, mode: c.int, errno: posix.Errno) {
    data.L = L
    lua.pushvalue(L, idx)
    data.ref = lua.L_ref(L, lua.REGISTRYINDEX)
    defer lua.pop(L, 1)

    switch metatable {
    case LUAFILE_HANDLE:
        writer, mode, errno = lua_file_to_stream(L, idx)
        return
    case "buffer":
        mode = -1
        writer = io.Writer {
            procedure = buffer_writer_stream_proc,
            data = data,
        }
        return
    case:
        panic("unreachable")
    }
}

lua_to_odin_string :: proc(L: ^lua.State, idx: lua.Index) -> string {
    cstr := lua.tostring(L, idx)
    ptr := cast(^byte) cstr
    s := strings.string_from_ptr(ptr, len(cstr))
    return s
}
