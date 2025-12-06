package main

import "core:fmt"
import "core:strings"
import os "core:os/os2"
import "core:bufio"
import lua "luajit"
import "luv"
import "ssh"
import "core:c"
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

// check luajit's string.buffer
// lua.testudata is not useful because it seems the string.buffer metatable is not in the registery
// as a hacky workaround we check for the existence of some methods until we figure how to properly do it
luajit_is_buffer :: proc "contextless" (L: ^lua.State) -> bool {
    methods := []cstring{"put", "tostring"}
    for method in methods {
        lua.getfield(L, -1, method)
        defer lua.pop(L, 1)
        if lua.type(L, -1) != .FUNCTION {
            return false
        }
    }
    return true
}

lua_check_userdata :: proc "contextless" (L: ^lua.State, metatable: cstring) -> bool {
    if metatable == "buffer" {
        if !luajit_is_buffer(L) {
            return false
        }
    } else if lua.L_testudata(L, -1, metatable) == nil {
        return false
    }
    return true
}

lua_check :: proc "contextless" (L: ^lua.State, idx: lua.Index, name: cstring, allowed_types: bit_set[lua.Type], msg: cstring, metatable: cstring = "") -> lua.Type {
    lua.getfield(L, idx, name)
    type := lua.type(L, -1)
    if .NIL in allowed_types && type == .NIL {
        return .NIL
    }
    fail := (type not_in allowed_types) ||
            (type == .USERDATA && !lua_check_userdata(L, metatable))
    if fail {
        type_name := lua.L_typename(L, -1)
        lua.L_error(L, "%s: %s, got %s", name, msg, type_name)
    }
    return type
}

// [target, table, field]
lua_check_and_set :: proc "contextless" (L: ^lua.State, name: cstring, allowed_types: bit_set[lua.Type], msg: cstring, metatable: cstring = "") {
    type := lua_check(L, -1, name, allowed_types, msg, metatable)
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
        userdata := cast(^Session) lua.touserdata(L, -1)
        session := userdata^
        lua.pop(L, 1) // [self]

        // self.args
        lua.getfield(L, 1, "args") // [self, args]
        args := lua.tostring(L, -1)
        lua.pop(L, 1) // [self]

        // self.pty
        pty: b32 = false
        if lua_check(L, 1, "pty", {.NIL, .BOOLEAN}, "expected boolean") == .BOOLEAN {
            pty = lua.toboolean(L, -1)
        }
        lua.pop(L, 1)

        stdin_type := lua_check(L, 1, "stdin", {.NIL, .STRING, .FUNCTION}, "expected string or callback")
        stdin_str: cstring
        #partial switch stdin_type {
        case .STRING:
            stdin_str = lua.tostring(L, -1)
            lua.pop(L, 1)
        case .FUNCTION:
            lua.call(L, 0, 1)
            if !lua.isstring(L, -1) {
                lua.L_error(L, "stdin callback: expected to return string, returned %s", lua.L_typename(L, -1))
            }
            stdin_str = lua.tostring(L, -1)
            lua.pop(L, 1)
        }

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

        // write stdin, if any
        // TODO: support string.buffer and lua files
        if stdin_str != "" {
            n := ssh.channel_write(channel, rawptr(stdin_str), u32(len(stdin_str)))
            if n == ssh.ERROR {
                lua.L_error(L, "%s", ssh.get_error(session))
            }
            status := ssh.channel_send_eof(channel)
            if status != ssh.OK {
                lua.L_error(L, "%s", ssh.get_error(session))
            }
        }

        stdout_type, stdout_idx := lua_check(L, 1, "stdout", {.NIL, .USERDATA}, "expected buffer", "buffer"), lua.gettop(L)
        stderr_type, stderr_idx := lua_check(L, 1, "stderr", {.NIL, .USERDATA}, "expected buffer", "buffer"), lua.gettop(L)

        stdout_done := stdout_type == .NIL
        stderr_done := stderr_type == .NIL || pty // ptys have stderr and stdout merged
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
        userdata := cast(^Session) lua.touserdata(L, 1)
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

    // @param args string
    // @param opts? table
    // sh(args, opts)
    lua.pushcfunction(L, proc "c" (L: ^lua.State) -> c.int {
        // [self, args, opts]
        num_args := lua.gettop(L)

        // session
        lua.L_checkudata(L, 1, METATABLE_SESSION)

        // args
        lua.L_checkstring(L, 2)

        // cmd
        lua.newtable(L) // [self, args, opts, cmd]
        lua.L_setmetatable(L, METATABLE_SSH_CMD)

        // cmd.session
        lua.pushvalue(L, 1) // [self, args, opts, cmd, self]
        lua.setfield(L, -2, "session") // [self, args, opts, cmd]

        // cmd.args
        lua.pushvalue(L, 2) // [self, args, opts, cmd, args]
        lua.setfield(L, -2, "args") // [self, args, opts, cmd]

        // cmd.opts
        if num_args >= 3 {
            context = runtime.default_context()
            lua.pushvalue(L, 3) // [self, args, opts, cmd, opts]
            lua_check_and_set(L, "pty", {.NIL, .BOOLEAN}, "expected boolean")
            lua_check_and_set(L, "stdin", {.NIL, .STRING, .FUNCTION}, "expected boolean or callback")
            lua_check_and_set(L, "stdout", {.NIL, .USERDATA}, "expected buffer", metatable="buffer")
            lua_check_and_set(L, "stderr", {.NIL, .USERDATA}, "expected buffer", metatable="buffer")
            lua.pop(L, 1) // pop opts
        }

        return 1
    })

    lua.setfield(L, -2, "sh")

    lua.setfield(L, -2, "__index")

    lua.pop(L, 1) // pop metatable
}

lash_ssh_connect :: proc "c" (L: ^lua.State) -> c.int {
    lua.L_checktype(L, 1, lua.TTABLE);

    _, host := lua_check(L, -1, "host", {.STRING}, "expected string"), lua_tostring_pop(L)
    _, user := lua_check(L, -1, "user", {.STRING}, "expected string"), lua_tostring_pop(L)

    lua_check(L, -1, "port", {.NUMBER}, "expected integer")
    port_float := lua.tonumber(L, -1)
    lua.pop(L, 1)
    port := c.int(port_float)
    is_integer := lua.Number(port) == port_float
    if !is_integer {
        lua.L_error(L, "port: expected integer, got floating point")
    }

    lua_check(L, -1, "auth", {.TABLE}, "expected table")
    _, auth_type := lua_check(L, -1, "type", {.STRING}, "Invalid auth type"), lua_tostring_pop(L)

    auth: Auth_Method
    switch auth_type {
    case "password":
        lua_check(L, -1, "password", {.STRING, .NIL}, "expected string")
        auth = Auth_Password { lua_tostring_pop(L) }
    case "publickey":
        lua_check(L, -1, "passphrase", {.STRING, .NIL}, "expected string")
        auth = Auth_Publickey_Auto { lua_tostring_pop(L) }
    case "agent":
        auth = Auth_Agent{}
        lua.pop(L, 1)
    // TODO: expand homedir ~
    case "publickey_file":
        _, passphrase := lua_check(L, -1, "passphrase", {.STRING, .NIL}, "expected string"), lua_tostring_pop(L)
        _, publickey  := lua_check(L, -1, "publickey", {.STRING}, "expected string"), lua_tostring_pop(L)
        _, privatekey := lua_check(L, -1, "privatekey", {.STRING}, "expected string"), lua_tostring_pop(L)
        auth = Auth_Publickey_File {
            public_path = publickey,
            private_path = privatekey,
            passphrase = passphrase,
        }
    case:
        lua.L_error(L, "unknown authentication method: '%s'", auth_type)
    }

    session, err := make_session(host, user, port, auth)
    if err != .None  {
        if session != nil {
            msg := ssh.get_error(session)
            if msg != "" {
                lua.pushstring(L, msg)
                ssh.free(session)
                lua.error(L)
            }
            ssh.free(session)
        }

        // handle EOF errors
        if auth_with_files, ok := auth.(Auth_Publickey_File); ok {
            #partial switch err {
            // TODO: distinguish between permissions and existence for EOF_*
            case .EOF_Publickey:
                lua.L_error(L, "can't read publickey: %s", auth_with_files.public_path)
            case .EOF_Privatekey:
                lua.L_error(L, "can't read privatekey: %s", auth_with_files.private_path)
            case .Cant_Import_Privatekey:
                lua.L_error(L, "error occursed while reading private key: %s", auth_with_files.private_path)
            case .Cant_Import_Publickey:
                lua.L_error(L, "error occursed while reading public key: %s", auth_with_files.private_path)
            }
        }

        msg := MAKE_SESSION_ERROR_MESSAGES[err]
        if msg != "" {
            lua.pushstring(L, msg)
            lua.error(L)
        } else {
            lua.L_error(L, "An unkown error occured while creating the session")
        }
    }

    userdata := lua.newuserdata(L, size_of(Session))
    userdata_session := cast(^Session) userdata
    userdata_session^ = session
    lua.L_setmetatable(L, METATABLE_SESSION) // lua 5.2 or luajit

    return 1
}

// a connected, authenticated ssh.Session
Session :: ssh.Session

// TODO: add AUTH_AGAIN
Make_Session_Error :: enum {
    None = int(ssh.Auth.SUCCESS),
    Auth_Denied = int(ssh.Auth.DENIED),   // has messages
    Auth_Partial = int(ssh.Auth.PARTIAL), // no message (I think)
    Cant_Connect,                         // has messages
    Cant_Check_Host,                      // has messages
    Host_Changed_Key,                     // no message. possible attack
    Cant_Make_Session,                    // no message since no session
    Host_Other_Key,                       // no message. possible attack.
    No_Known_Hosts_File,                  // no message. what? why dont you have the file???
    Unknown_Host,                         // no message. you have to trust it somehwere else
    EOF_Publickey,                        // no messages. casued by unreadable key file
    EOF_Privatekey,                       // no messages. casued by unreadable key file
    Cant_Import_Publickey,                // no messages. Only logged
    Cant_Import_Privatekey,               // no messages. Only logged
    Auth_Error = int(ssh.Auth.ERROR),     // has messages
}

// @(rodata)
MAKE_SESSION_ERROR_MESSAGES := #partial [Make_Session_Error]cstring {
    .Auth_Denied = "Authentication failed",
    .Auth_Partial = "You've been partially authenticated, you still have to use another method",
    .Cant_Make_Session = "Can't create ssh session",
    .Host_Changed_Key = "POSSIBLE ATTACK: Host key for server changed",
    .Host_Other_Key = "POSSIBLE ATTACK: The host key for this server was not found but an other type of key exists",
    .No_Known_Hosts_File = "Could not find known host file",
    .Unknown_Host = "The host is unknown",
    .Auth_Error = "A serious error happened",
}

Auth_Password :: struct {
    password: cstring
}

Auth_Publickey_Auto :: struct {
    passphrase: cstring, // can be nil btw
}

Auth_Publickey_File :: struct {
    public_path: cstring,
    private_path: cstring,
    passphrase: cstring, // can be nil btw
}

Auth_Agent :: struct { }

Auth_Method :: union {
    Auth_Password,
    Auth_Publickey_Auto,
    Auth_Publickey_File,
    Auth_Agent,
}

// a session may be returned even if err != .None in case ssh.get_error(session) returns something useful.
// Don't forget to call ssh.free(session) after you copy the message. The error and sessio have the same lifetime.
make_session :: proc "contextless" (host: cstring, user: cstring, port: c.int, auth_method: Auth_Method) -> (Session, Make_Session_Error) {
    session := ssh.new()
    if session == nil {
        return nil, .Cant_Make_Session
    }
    // verbosity := 4
    // ssh.options_set(session, .LOG_VERBOSITY, &verbosity)
    ssh.options_set(session, .HOST, rawptr(host))
    // If you dont pass user then it defaults to current user
    // However, things like ssh.userauth_publickey_auto()
    // break with a cryptic parsing error when then user is nil
    // Its so lame I spent like an hour debugging this
    // I'm NOT removing this comment as a constant reminder of agony
    // (perhaps should've compiled with -vet-unused-varaibles)
    ssh.options_set(session, .USER, rawptr(user))
    port := port
    ssh.options_set(session, .PORT, &port)

    status := ssh.connect(session)
    if status != ssh.OK {
        return session, .Cant_Connect
    }

    state := ssh.session_is_known_server(session);
    switch state {
    case .OK:
    case .ERROR:
        return session, .Cant_Check_Host
    case .CHANGED:
        return session, .Host_Changed_Key
    case .OTHER:
        return session, .Host_Other_Key
    case .NOT_FOUND:
        return session, .No_Known_Hosts_File
    case .UNKNOWN:
        return session, .Unknown_Host
    }

    // should we make auth a seperate function?
    err: Make_Session_Error
    auth_status: c.int
    switch auth in auth_method {
    case Auth_Password:
        auth_status = ssh.userauth_password(session, user, auth.password)
        err = Make_Session_Error(ssh.Auth(auth_status))

    case Auth_Publickey_Auto:
        auth_status = ssh.userauth_publickey_auto(session, nil, auth.passphrase)
        err = Make_Session_Error(ssh.Auth(auth_status))

    case Auth_Agent:
        auth_status = ssh.userauth_agent(session, nil)
        err = Make_Session_Error(ssh.Auth(auth_status))

    case Auth_Publickey_File:
        // grab public key
        pub_key: ssh.Key
        status = ssh.pki_import_pubkey_file(auth.public_path, &pub_key)
        if status == ssh.EOF {
            err = .EOF_Publickey
            break;
        } else if status != ssh.OK {
            err = .Cant_Import_Publickey
            break
        }
        defer ssh.key_free(pub_key)

        // check server accepts public key
        auth_status = ssh.userauth_try_publickey(session, nil, pub_key)
        err = Make_Session_Error(ssh.Auth(auth_status))
        if err != .None {
            break;
        }

        // grab private key
        priv_key: ssh.Key
        status = ssh.pki_import_privkey_file(auth.private_path, auth.passphrase, nil, nil, &priv_key)
        if status == ssh.EOF {
            err = .EOF_Privatekey
            break
        } else if status != ssh.OK {
            err = .Cant_Import_Privatekey
            break
        }
        defer ssh.key_free(priv_key)

        auth_status = ssh.userauth_publickey(session, nil, priv_key)
        err = Make_Session_Error(ssh.Auth(auth_status))
    }

    if err != .None {
        ssh.disconnect(session)
    }

    return session, err
}

// ssh.get_error(session) *sometimes* gives messages
Session_Exec_Error :: enum {
    None,
    Cant_Create_Channel, // no message, but noticed it happens when you're not authenticated
    Cant_Open_Session, // has messages
    Cant_Request_Exec, // has messages
    Cant_Request_Pty, // has messages
}

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
    lua.setfield(L, 1, "_get_metatable")

    // @param prompt string?
    // @param opts? {blind?: boolean}
    // @return (string?, error)
    // input()
    lua.pushcfunction(L, proc "c" (L: ^lua.State) -> c.int {
        num_args := lua.gettop(L)
        if num_args < 1 {
            lua.L_error(L, "Expected at least 1 argument")
        }

        has_prompt := lua.isstring(L, 1)
        if !lua.isnil(L, 1) && !has_prompt {
            lua.L_error(L, "prompt: expected string, got %s", lua.L_typename(L, 1))
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
                    lua.L_error(L, "echo: expected boolean, got %s", lua.L_typename(L, -1))
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
                lua.L_error(L, "EOF when reading a line")
            }
            msg := fmt.caprint(err)
            lua.pushstring(L, msg)
            free_all(context.temp_allocator)
            lua.error(L)
        }

        line := bufio.scanner_text(&stdin_scanner)
        lua.pushlstring(L, strings.unsafe_string_to_cstring(line), len(line))

        // turn back echo after we turn it off
        if !want_echo {
            term.c_lflag += { .ECHO }
            posix.tcsetattr(stdin_fd, .TCSANOW, &term)
            fmt.println()
        }

        return 1
    })
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
