package main

import lua "luajit"
import "ssh"
import "core:c"
import "core:io"
import "base:runtime"
import "core:sys/posix"
import "core:slice"

METATABLE_SESSION :: "SshSession"
METATABLE_SSH_CMD :: "SshCmd"

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
make_session :: proc (host: cstring, user: cstring, port: c.int, auth_method: Auth_Method) -> (ssh.Session, Make_Session_Error) {
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
session_exec :: proc "contextless" (session: ssh.Session, cmd: cstring, want_pty: b32) -> (ssh.Channel, Session_Exec_Error) {
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



// A channel along with its callbacks
Channel_Info :: struct {
    channel: ssh.Channel,
    callbacks: ssh.Channel_Callbacks_Struct,
    stdout_writer: io.Writer,
    stderr_writer: io.Writer,
    // a place for the buffer_writer struct to live in case io.Writer is a buffer
    stdout_data: Buffer_Writer,
    stderr_data: Buffer_Writer,
}

channel_info_init :: proc (info: ^Channel_Info) {
    // zero out callbacks or you'll call nonsense
    // Took me a while to figure the cause of those segfaults :(
    info.callbacks = ssh.Channel_Callbacks_Struct{}
    ssh.callbacks_init(&info.callbacks)
    info.callbacks.userdata = info
    info.stdout_writer = discard_stream
    info.stderr_writer = discard_stream
}

// TODO: should we just make a channel a writer?
write_to_channel :: proc (reader: io.Reader, channel: ssh.Channel) -> (io.Error, c.int) {
    buf: [1024]u8 = ---
    loop: for {
        bytes_read, err := io.read(reader, buf[:])
        if bytes_read == 0 {
            #partial switch err {
            case .None:
            case .EOF : break loop
            case      : return err, ssh.OK
            }
        }

        offset := 0
        for offset < bytes_read {
            s := buf[offset:bytes_read]
            n := ssh.channel_write(channel, raw_data(s), u32(len(s)))
            if n == ssh.ERROR {
                return .None, ssh.ERROR
            }
            offset += int(n)
        }
    }
    status := ssh.channel_send_eof(channel)
    return .None, status
}

ssh_cmd_start :: proc "c" (L: ^lua.State) -> c.int {
    context = runtime.default_context()
    lua.L_checktype(L, 1, .TABLE)

    lua_check_with_udata(L, 1, "session", {.USERDATA}, "expected SshSession", {METATABLE_SESSION})
    session_ptr := cast(^ssh.Session) lua.touserdata(L, -1)
    session := session_ptr^
    lua.pop(L, 1)

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

    stdin_type, stdin_metatable := lua_check_with_udata(L, 1, "stdin", {.NIL, .STRING, .FUNCTION, .USERDATA}, "expected string, callback, buffer, or file", []cstring{"buffer", LUAFILE_HANDLE})
    stdin_bytes: [^]byte
    stdin_len: int
    stdin_reader: io.Reader
    // TODO: use io.Stream even in string
    #partial switch stdin_type {
    case .STRING:
        str := lua.tostring(L, -1)
        stdin_bytes, stdin_len = cast([^]u8) str, len(str)
        lua.pop(L, 1)

    case .FUNCTION:
        lua.call(L, 0, 1)
        if !lua.isstring(L, -1) {
            return lua.L_error(L, "stdin callback: expected to return string, returned %s", lua.L_typename(L, -1))
        }
        str := lua.tostring(L, -1)
        stdin_bytes, stdin_len = cast([^]u8) str, len(str)
        lua.pop(L, 1)

    case .USERDATA:
        switch stdin_metatable {
        case "buffer":
            lua.getfield(L, -1, "ref")
            lua.pushvalue(L, -2)
            lua.call(L, 1, 2)
            stdin_len = int(lua.tointeger(L, -1))
            stdin_bytes = cast([^]u8) lua.tostring(L, -2)
            lua.pop(L, 4) // buf, ref, bytes, len

        case LUAFILE_HANDLE:
            reader, mode, errno := lua_file_to_stream(L, -1)
            stdin_reader = reader
            if errno != .NONE {
                return lua_error_from_enum(L, errno)
            }
            if mode == posix.O_WRONLY {
                return lua.L_error(L, "stdin is not a readable file descriptor")
            }
        }
    }

    // create channel. No need to set it to "blocking" that's just a dumb
    // confusing alias for making the session channel. There are no
    // non-blocking channels. Only non-blocking session
    channel, err := session_exec(session, args, pty)
    if err != .None {
        msg := ssh.get_error(session)
        if msg != "" {
            lua_push_errmsg(L, msg)
            return lua.error(L)
        } else {
            return lua_error_from_enum(L, err)
        }
    }
    ssh.set_blocking(session, false)

    info := cast(^Channel_Info) lua.newuserdata(L, size_of(Channel_Info))
    channel_info_init(info)
    info.channel = channel
    lua.setfield(L, 1, "_channel_info")

    set_stdio :: proc (L: ^lua.State, idx: lua.Index, bw: ^Buffer_Writer, metatable: cstring, name: cstring) -> (io.Writer, bool) {
        writer, mode, errno := lua_stdio_to_writer(L, idx, bw, metatable)
        if errno != .NONE {
            lua_push_error_from_enum(L, errno)
            return writer, false
        }
        if mode == posix.O_RDONLY {
            lua.pushfstring(L, "%s is not a writable file descriptor", name)
            return writer, false
        }
        return writer, true
    }

    stdout_type, stdout_metatable := lua_check_with_udata(L, 1, "stdout", {.NIL, .USERDATA}, "expected buffer or file", []cstring{"buffer", LUAFILE_HANDLE})
    stdout_idx := lua.gettop(L)
    stderr_type, stderr_metatable := lua_check_with_udata(L, 1, "stderr", {.NIL, .USERDATA}, "expected buffer or file", []cstring{"buffer", LUAFILE_HANDLE})
    stderr_idx := lua.gettop(L)

    stdout_done := stdout_type == .NIL
    stderr_done := stderr_type == .NIL || pty // ptys have stderr and stdout merged

    if !stdout_done {
        ok: bool
        info.stdout_writer, ok = set_stdio(L, stdout_idx, &info.stdout_data, stdout_metatable, "stdout")
        if !ok do lua.error(L)
    }

    if !stderr_done {
        ok: bool
        info.stderr_writer, ok = set_stdio(L, stderr_idx, &info.stderr_data, stderr_metatable, "stderr")
        if !ok do lua.error(L)
    }

    on_data :: proc "c" (_: ssh.Session, _: ssh.Channel, data: rawptr, len: c.uint32_t, is_stderr: b32, userdata: rawptr) -> c.int {
        context = runtime.default_context()
        info := cast(^Channel_Info) userdata
        writer: io.Writer
        if is_stderr {
            writer = info.stderr_writer
        } else {
            writer = info.stdout_writer
        }
        data_byte_ptr := cast(^byte) data
        buf := slice.from_ptr(data_byte_ptr, int(len))
        n, _ := io.write(writer, buf)
        return c.int(n)
    }

    info.callbacks.channel_data_function = on_data
    ssh.set_channel_callbacks(channel, &info.callbacks)

    // write stdin, if any
    if stdin_bytes != nil {
        n := ssh.channel_write(channel, rawptr(stdin_bytes), u32(stdin_len))
        if n == ssh.ERROR {
            return lua.L_error(L, "%s", ssh.get_error(session))
        }
        status := ssh.channel_send_eof(channel)
        if status != ssh.OK {
            return lua.L_error(L, "%s", ssh.get_error(session))
        }
    } else if stdin_metatable == LUAFILE_HANDLE {
        io_err, ssh_err := write_to_channel(stdin_reader, channel)
        if io_err != .None {
            return lua_error_from_enum(L, io_err)
        } else if ssh_err != ssh.OK {
            return lua.L_error(L, "%s", ssh.get_error(session))
        }
    }

    return 0
}

ssh_cmd_wait :: proc "c" (L: ^lua.State) -> c.int {
    context = runtime.default_context()
    lua.L_checktype(L, 1, .TABLE)
    lua_check(L, 1, "_channel_info", {.USERDATA}, "Somebody touched internals! Moron")
    info := cast(^Channel_Info) lua.touserdata(L, -1)

    for !ssh.channel_is_eof(info.channel) {
        ssh.channel_poll(info.channel, false)
        ssh.channel_poll(info.channel, true)
    }

    return 0
}

ssh_cmd_run :: proc "c" (L: ^lua.State) -> c.int {
    ssh_cmd_start(L)
    ssh_cmd_wait(L)
    return 0
}

ssh_cmd_gc :: proc "c" (L: ^lua.State) -> c.int {
    type := lua_check(L, 1, "_channel_info", {.USERDATA, .NIL}, "Somebody touched internals! Moron")
    if type == .NIL {
        return 0
    }

    info := cast(^Channel_Info) lua.touserdata(L, -1)
    ssh.channel_free(info.channel)
    lua_stream_data_unref(&info.stdout_data)
    lua_stream_data_unref(&info.stderr_data)

    return 0
}

define_ssh_cmd_metatable :: proc(L: ^lua.State) {
    lua.L_newmetatable(L, METATABLE_SSH_CMD)

    // __index
    lua.newtable(L)

    lua.pushcfunction(L, ssh_cmd_run)
    lua.setfield(L, -2, "run")

    lua.pushcfunction(L, ssh_cmd_start)
    lua.setfield(L, -2, "start")

    lua.pushcfunction(L, ssh_cmd_wait)
    lua.setfield(L, -2, "wait")


    lua.setfield(L, -2, "__index")
    lua.pop(L, 1) // pop metatable
}

ssh_session_gc :: proc "c" (L: ^lua.State) -> c.int {
    userdata := cast(^ssh.Session) lua.touserdata(L, 1)
    session := userdata^
    if ssh.is_connected(session) {
        ssh.disconnect(session)
    }
    ssh.free(session)
    return 0
}

// @param args string
// @param opts? table
// sh(args, opts)
ssh_session_sh :: proc "c" (L: ^lua.State) -> c.int {
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
        lua_check_and_set(L, "stdin", {.NIL, .STRING, .FUNCTION, .USERDATA}, "expected string, callback, buffer, or file", []cstring{"buffer", LUAFILE_HANDLE})
        lua_check_and_set(L, "stdout", {.NIL, .USERDATA}, "expected buffer or file", metatables=[]cstring{"buffer", LUAFILE_HANDLE})
        lua_check_and_set(L, "stderr", {.NIL, .USERDATA}, "expected buffer or file", metatables=[]cstring{"buffer", LUAFILE_HANDLE})
        lua.pop(L, 1) // pop opts
    }
    return 1
}

define_ssh_session_metatable :: proc(L: ^lua.State) {
    lua.L_newmetatable(L, METATABLE_SESSION)

    lua.pushcfunction(L, ssh_session_gc)
    lua.setfield(L, -2, "__gc")

    lua.newtable(L)

    lua.pushcfunction(L, ssh_session_sh)
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
        return lua.L_error(L, "port: expected integer, got floating point")
    }

    lua_check(L, -1, "auth", {.TABLE}, "expected table")
    _, auth_type := lua_check(L, -1, "type", {.STRING}, "Invalid auth type"), lua_tostring_pop(L)

    context = runtime.default_context()
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
    case "publickey_file":
        _, passphrase := lua_check(L, -1, "passphrase", {.STRING, .NIL}, "expected string"), lua_tostring_pop(L)
        _, publickey  := lua_check(L, -1, "publickey", {.STRING}, "expected string"), lua_tostring_pop(L)
        _, privatekey := lua_check(L, -1, "privatekey", {.STRING}, "expected string"), lua_tostring_pop(L)

        starts_with_tilde :: #force_inline proc "contextless" (str: cstring) -> bool {
            s := cast([^]u8)str
            return s[0] == '~'
        }

        // calls string.gsub(str, "^~", home)
        expand_home :: #force_inline proc "contextless" (L: ^lua.State, str: cstring, home: cstring) -> cstring {
            lua.getglobal(L, "string")
            lua.getfield(L, -1, "gsub")
            lua.pushstring(L, str) // x
            lua.pushstring(L, "^~")
            lua.pushstring(L, home)
            lua.call(L, 3, 1)
            return lua.tostring(L, -1)
        }

        if starts_with_tilde(publickey) || starts_with_tilde(privatekey) {
            // error if $HOME is not defined
            lua.getglobal(L, "os")
            lua.getfield(L, -1, "getenv")
            lua.pushstring(L, "HOME")
            lua.call(L, 1, 1)
            if lua.isnil(L, -1) {
                return lua.L_error(L, "$HOME is not defined")
            }

            home := lua.tostring(L, -1)
            if starts_with_tilde(publickey) {
                publickey = expand_home(L, publickey, home)
            }
            if starts_with_tilde(privatekey) {
                privatekey = expand_home(L, privatekey, home)
            }
        }

        auth = Auth_Publickey_File {
            passphrase = passphrase,
            public_path = publickey,
            private_path = privatekey,
        }

    case:
        return lua.L_error(L, "unknown authentication method: '%s'", auth_type)
    }

    session, err := make_session(host, user, port, auth)
    if err != .None  {
        if session != nil {
            msg := ssh.get_error(session)
            if msg != "" {
                lua_push_errmsg(L, msg)
                ssh.free(session)
                return lua.error(L)
            }
            ssh.free(session)
        }

        // handle EOF errors
        if auth_with_files, ok := auth.(Auth_Publickey_File); ok {
            #partial switch err {
            // TODO: distinguish between permissions and existence for EOF_*
            case .EOF_Publickey:
                return lua.L_error(L, "can't read publickey: %s", auth_with_files.public_path)
            case .EOF_Privatekey:
                return lua.L_error(L, "can't read privatekey: %s", auth_with_files.private_path)
            case .Cant_Import_Privatekey:
                return lua.L_error(L, "error occursed while reading private key: %s", auth_with_files.private_path)
            case .Cant_Import_Publickey:
                return lua.L_error(L, "error occursed while reading public key: %s", auth_with_files.private_path)
            }
        }

        msg := MAKE_SESSION_ERROR_MESSAGES[err]
        if msg != "" {
            lua_push_errmsg(L, msg)
            return lua.error(L)
        } else {
            return lua.L_error(L, "An unkown error occured while creating the session")
        }
    }

    userdata := lua.newuserdata(L, size_of(ssh.Session))
    userdata_session := cast(^ssh.Session) userdata
    userdata_session^ = session
    lua.L_setmetatable(L, METATABLE_SESSION) // lua 5.2 or luajit

    return 1
}
