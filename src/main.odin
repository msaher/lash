package main

import "core:fmt"
import "core:strings"
import os "core:os/os2"
import lua "luajit"
import "luv"
import "ssh"
import "core:c"
import "core:time"
import "core:sys/posix"
import "base:runtime"
import "core:c/libc"

USAGE :: "run FILENAME"

METATABLE_SESSION :: "SshSession"
METATABLE_SSH_CMD :: "SshCmd"

lua_error_from_enum :: proc "contextless" (L: ^lua.State, err: any) {
    context = runtime.default_context()
    msg := fmt.caprint(err)
    lua.pushstring(L, msg)
    delete(msg)
    lua.error(L)
}

// TODO: handle cases
is_host_known_and_ok :: proc(session: ssh.Session) -> (bool, cstring) {
    state := ssh.session_is_known_server(session);
    #partial switch state {
    case .OK:
        return true, ""
    case .ERROR:
        return false, ssh.get_error(session)
    case:
        return false, ""
    }
}

define_ssh_cmd_metatable :: proc(L: ^lua.State) {
    lua.L_newmetatable(L, METATABLE_SSH_CMD)

    // __index
    lua.newtable(L)

    // run
    // cmd:run()
    lua.pushcfunction(L, proc "c" (L: ^lua.State) -> c.int {
        context = runtime.default_context()
        lua.L_checktype(L, 1, .TABLE) // [self]
        lua.getfield(L, 1, "session") // [self, session]
        userdata := transmute(^Session) lua.touserdata(L, -1)
        session := userdata^
        lua.pop(L, 1) // [self]

        // self.args
        lua.getfield(L, 1, "args") // [self, args]
        args := lua.tostring(L, -1)
        lua.pop(L, 1) // [self]

        // self.pty
        pty: b32 = false
        lua.getfield(L, 1, "pty") // [self, pty]
        if !lua.isnil(L, -1) {
            if lua.isboolean(L, -1) {
                pty = lua.toboolean(L, -1)
            } else {
                lua.L_error(L, "pty: expected boolean, got %s", lua.L_typename(L, -1))
            }
        }
        lua.pop(L, 1)

        channel, err := session_exec_no_read(session, args, pty)
        if err != .None {
            msg := ssh.get_error(session)
            if msg != nil {
                lua.pushstring(L, msg)
                lua.error(L)
            } else {
                lua_error_from_enum(L, err)
            }
        }

        // [self, stdout, stderr, stdin]
        lua.getfield(L, 1, "stdout")
        lua.getfield(L, 1, "stderr")
        lua.getfield(L, 1, "stdin")
        stdout_idx: lua.Index = 2
        stderr_idx: lua.Index = 3
        stdin_idx: lua.Index = 4

        // write stdin, if any
        if !lua.isnil(L, stdin_idx) {
            // TODO: support string.buffer and lua files
            stdin_str := lua.tostring(L, stdin_idx) // only strings supported right now
            n := ssh.channel_write(channel, rawptr(stdin_str), u32(len(stdin_str)))
            if n == ssh.ERROR {
                lua.L_error(L, "%s", ssh.get_error(session))
            }
            status := ssh.channel_send_eof(channel)
            if status != ssh.OK {
                lua.L_error(L, "%s", ssh.get_error(session))
            }
        }

        stdout_done := lua.isnil(L, stdout_idx)
        stderr_done := lua.isnil(L, stderr_idx) || pty // ptys have stderr and stdout merged
        buf: [1024]u8 = ---
        n: c.int
        for !stdout_done || !stderr_done {

            if !stdout_done {
                n = ssh.channel_read(channel, rawptr(&buf), len(buf), false)
                if n <= 0 {
                    stdout_done = true
                }
                // append
                lua.getfield(L, stdout_idx, "put")
                lua.pushvalue(L, stdout_idx)
                lua.pushlstring(L, cstring(raw_data(buf[:n])), uint(n))
                lua.call(L, 2, 0)
            }

            if !stderr_done {
                n = ssh.channel_read(channel, rawptr(&buf), len(buf), true)
                if n <= 0 {
                    stderr_done = true
                }
                // append
                lua.getfield(L, stderr_idx, "put")
                lua.pushvalue(L, stderr_idx)
                lua.pushlstring(L, cstring(raw_data(buf[:n])), uint(n))
                lua.call(L, 2, 0)
            }
        }

        exit_code: c.uint32_t = ---
        exit_signal: [^]u8 = ---
        status := ssh.channel_get_exit_state(channel, &exit_code, &exit_signal, nil)
        ssh.channel_close(channel)
        ssh.channel_free(channel)

        if status != ssh.OK {
            msg := ssh.get_error(session)
            lua.pushstring(L, msg)
            lua.error(L)
        }

        // exit_state (to be returned)
        lua.newtable(L)
        lua.pushinteger(L, lua.Integer(exit_code))
        lua.setfield(L, -2, "exit_code")
        lua.pushstring(L, cstring(exit_signal))
        lua.setfield(L, -2, "exit_signal")

        did_save_stderr := !lua.isnil(L, stderr_idx)
        if did_save_stderr {
            lua.getfield(L, stderr_idx, "tostring")
            lua.pushvalue(L, stderr_idx)
            lua.call(L, 1, 1)
            lua.setfield(L, -2, "stderr")
        }

        // save reference to exit_state in self
        lua.pushvalue(L, -2)
        lua.setfield(L, 1, "exit_state")

        if exit_signal != nil {
            libc.free(exit_signal)
        }
        return 1
    })
    lua.setfield(L, -2, "run")

    lua.setfield(L, -2, "__index")
    lua.pop(L, 1) // pop metatable
}

define_ssh_session_metatable :: proc(L: ^lua.State) {
    lua.L_newmetatable(L, METATABLE_SESSION)

    // __gc
    lua.pushcfunction(L, proc "c" (L: ^lua.State) -> c.int {
        userdata := transmute(^Session) lua.touserdata(L, 1)
        session := userdata^
        if ssh.is_connected(session) {
            ssh.disconnect(session)
        }
        ssh.free(session)
        return 0
    })
    lua.setfield(L, -2, "__gc")

    // __index
    lua.newtable(L)

    // run(args, opts)
    lua.pushcfunction(L, proc "c" (L: ^lua.State) -> c.int {
        // [self, args, opts]
        userdata := transmute(^Session) lua.touserdata(L, 1)
        session := userdata^
        lua.L_checkstring(L, 2) // args is string

        // TODO: opts

        lua.newtable(L) // [self, args, opts, cmd]
        lua.L_setmetatable(L, METATABLE_SSH_CMD)
        lua.pushvalue(L, 1) // [self, args, opts, cmd, self]
        lua.setfield(L, -2, "session") // [self, args, opts, cmd]
        lua.pushvalue(L, 2) // [self, args, opts, cmd, args]

        lua.setfield(L, -2, "args") // [self, args, opts, cmd]

        return 1
    })
    lua.setfield(L, -2, "sh")

    lua.setfield(L, -2, "__index")

    lua.pop(L, 1) // pop metatable
}

lash_ssh_connect :: proc "c" (L: ^lua.State) -> c.int {
    lua.L_checktype(L, 1, lua.TTABLE);

    // table.host
    lua.getfield(L, 1, "host")
    idx := lua.gettop(L)
    if !lua.isstring(L, idx) {
        lua.L_error(L, "host: expected string, got %s", lua.L_typename(L, idx))
    }
    host := lua.tostring(L, idx)
    lua.pop(L, 1)

    // table.user
    lua.getfield(L, 1, "user")
    idx = lua.gettop(L)
    if !lua.isstring(L, idx) {
        lua.L_error(L, "user: expected string, got %s", lua.L_typename(L, idx))
    }
    user := lua.tostring(L, idx)
    lua.pop(L, 1)

    // table.port
    lua.getfield(L, 1, "port")
    idx = lua.gettop(L)
    if !lua.isnumber(L, idx) {
        lua.L_error(L, "port: expected integer, got %s", lua.L_typename(L, idx))
    }
    port_float := lua.tonumber(L, idx)
    port := c.int(port_float)
    is_integer := lua.Number(port) == port_float
    if !is_integer {
        lua.L_error(L, "port: expected integer, got floating point")
    }
    lua.pop(L, 1)

    // TODO: support other auth methods
    // table.password
    lua.getfield(L, 1, "password")
    idx = lua.gettop(L)
    if !lua.isstring(L, idx) {
        lua.L_error(L, "password: expected string, got %s", lua.L_typename(L, idx))
    }
    password := lua.tostring(L, idx)
    lua.pop(L, 1)

    context = runtime.default_context()
    session, err := make_session(host, user, port, password)

    msg: cstring = ""
    switch e in err {
    case Cant_Connect_Error:
        msg = e.msg
    case Bad_Host_Error:
        if e.msg == "" {
            msg = "Bad host error: Unknown reason"
        } else {
            msg = e.msg
        }
    case Connection_Session_General_Error:
        msg = Connection_Session_Messages[e]
    }

    if err != nil {
        // msg lifetime is same as session
        lua.pushfstring(L, msg) // copy to lua
        if session != nil {
            ssh.free(session)
        }
        lua.error(L)
    }

    userdata := lua.newuserdata(L, size_of(Session))
    userdata_session := transmute(^Session) userdata
    userdata_session^ = session
    lua.L_setmetatable(L, METATABLE_SESSION) // lua 5.2 or luajit

    return 1
}

Cant_Connect_Error :: struct {msg: cstring}
Bad_Host_Error :: struct {msg: cstring}

// connected, authenticated session
Session :: ssh.Session

Connection_Session_General_Error :: enum {
    Denied = int(ssh.Auth.DENIED),
    Partial = int(ssh.Auth.PARTIAL),
    Error = int(ssh.Auth.ERROR),
    Cant_Make_Session,
}

@(rodata)
Connection_Session_Messages := [Connection_Session_General_Error]cstring {
    .Error = "A serious error happened",
    .Denied = "Authentication failed",
    .Partial = "You've been partially authenticated, you still have to use another method",
    .Cant_Make_Session = "Can't create ssh session",
}

Connected_Session_Error :: union {
    Connection_Session_General_Error,
    Cant_Connect_Error,
    Bad_Host_Error,
}

make_session :: proc (host: cstring, user: cstring, port: c.int, password: cstring) -> (Session, Connected_Session_Error) {
    session := ssh.new()
    if session == nil {
        return nil, .Cant_Make_Session
    }
    // verbosity := ssh.LOG_PROTOCOL
    // ssh.options_set(session, .LOG_VERBOSITY, &verbosity)
    ssh.options_set(session, .HOST, rawptr(host))
    port := port
    ssh.options_set(session, .PORT, &port)

    status := ssh.connect(session)
    if status != ssh.OK {
        msg := ssh.get_error(session)
        return nil, Cant_Connect_Error{msg = msg}
    }

    is_ok, msg := is_host_known_and_ok(session)
    if !is_ok {
        return nil, Bad_Host_Error{msg=msg}
    }

    auth_int := ssh.userauth_password(session, user, password)
    auth := ssh.Auth(auth_int)
    if auth != .SUCCESS {
        ssh.free(session)
        return nil, Connection_Session_General_Error(auth)
    }
    return session, nil
}

// ssh.get_error(session) *sometimes* gives messages
Session_Exec_Error :: enum {
    None,
    Cant_Create_Channel, // no message, but noticed it happens when you're not authenticated
    Cant_Open_Session, // has messages
    Cant_Request_Exec, // has messages
    Cant_Request_Pty, // has messages
}

// TODO: ssh_channel_request_pty
// must close and free channel
session_exec_no_read :: proc "contextless" (session: ssh.Session, cmd: cstring, want_pty: b32) -> (ssh.Channel, Session_Exec_Error) {
    channel := ssh.channel_new(session)
    if channel == nil {
        return nil, .Cant_Create_Channel
    }
    rc := ssh.channel_open_session(channel)
    if rc != ssh.OK {
        return nil, .Cant_Open_Session
    }

    if want_pty {
        rc = ssh.channel_request_pty(channel)
        if rc != ssh.OK {
            return nil, .Cant_Request_Pty
        }
    }

    rc = ssh.channel_request_exec(channel, cmd)
    if rc != ssh.OK {
        return nil, .Cant_Request_Exec
    }

    return channel, .None,
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

    // metatable
    define_ssh_cmd_metatable(L)
    define_ssh_session_metatable(L)

    lua.newtable(L) // [lash, ssh]
    lua.pushcfunction(L, lash_ssh_connect) // [lash, ssh, connect]
    lua.setfield(L, 2, "connect") // [lash, ssh]
    lua.setfield(L, 1, "ssh") // [lash]

    // __get_metatable
    lua.pushcfunction(L, proc "c" (L: ^lua.State) -> c.int {
        mt_name := lua.tostring(L, 1)
        lua.L_getmetatable(L, mt_name)
        return 1
    })
    lua.setfield(L, 1, "_get_metatable") // [lash, ssh]

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
