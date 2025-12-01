package ssh
import "core:c"

// TODO: bind deprecated functions

foreign import ssh {
    "../libssh-0.11.3/build/src/libssh.a",
    "system:ssl",
    "system:crypto",
    "system:gssapi_krb5",
    "system:z",
}

Mode :: c.int

Counter_Struct :: struct {
    in_bytes: c.uint64_t,
    out_bytes: c.uint64_t,
    in_packets: c.uint64_t,
    out_packets: c.uint64_t,
}

Counter :: ^Counter_Struct

Agent :: distinct rawptr
Buffer :: distinct rawptr
Channel :: distinct rawptr
Message :: distinct rawptr
Pcap_File :: distinct rawptr
Key :: distinct rawptr
Scp :: distinct rawptr
Session :: distinct rawptr
String :: distinct rawptr
Event :: distinct rawptr
Connector :: distinct rawptr
Gssapi_Creds :: distinct rawptr


INVALID_SOCKET :: Socket(-1)

Kex_Types :: enum c.int {
	KEX=0,
	HOSTKEYS,
	CRYPT_C_S,
	CRYPT_S_C,
	MAC_C_S,
	MAC_S_C,
	COMP_C_S,
	COMP_S_C,
	LANG_C_S,
	LANG_S_C
}

CRYPT	:: 2
MAC		:: 3
COMP	:: 4
LANG	:: 5

Auth :: enum c.int {
	SUCCESS=0,
	DENIED,
	PARTIAL,
	INFO,
	AGAIN,
	ERROR=-1
}

/* auth flags */
AUTH_METHOD_UNKNOWN		:: 0x0000
AUTH_METHOD_NONE		:: 0x0001
AUTH_METHOD_PASSWORD	:: 0x0002
AUTH_METHOD_PUBLICKEY	:: 0x0004
AUTH_METHOD_HOSTBASED	:: 0x0008
AUTH_METHOD_INTERACTIVE :: 0x0010
AUTH_METHOD_GSSAPI_MIC	:: 0x0020

/* messages */
Requests :: enum c.int {
	AUTH=1,
	CHANNEL_OPEN,
	CHANNEL,
	SERVICE,
	GLOBAL
}

Channel_Type :: enum c.int {
	UNKNOWN=0,
	SESSION,
	DIRECT_TCPIP,
	FORWARDED_TCPIP,
	X11,
	AUTH_AGENT
}

Channel_Request :: enum c.int {
	UNKNOWN=0,
	PTY,
	EXEC,
	SHELL,
	ENV,
	SUBSYSTEM,
	WINDOW_CHANGE,
	X11
}

Global_Requests :: enum c.int {
	UNKNOWN=0,
	TCPIP_FORWARD,
	CANCEL_TCPIP_FORWARD,
	KEEPALIVE,
	NO_MORE_SESSIONS
}

Publickey_State :: enum c.int {
	ERROR=-1,
	NONE=0,
	VALID=1,
	WRONG=2
}

/* Status flags */
/** Socket is closed */
CLOSED :: 0x01
/** Reading to socket won't block */
READ_PENDING :: 0x02
/** Session was closed due to an error */
CLOSED_ERROR :: 0x04
/** Output buffer not empty */
WRITE_PENDING :: 0x08

Server_Known :: enum c.int {
	ERROR=-1,
	NOT_KNOWN=0,
	KNOWN_OK,
	KNOWN_CHANGED,
	FOUND_OTHER,
	FILE_NOT_FOUND
}

Known_Hosts :: enum c.int {
    /**
     * There had been an error checking the host.
     */
    ERROR = -2,

    /**
     * The known host file does not exist. The host is thus unknown. File will
     * be created if host key is accepted.
     */
    NOT_FOUND = -1,

    /**
     * The server is unknown. User should confirm the public key hash is
     * correct.
     */
    UNKNOWN = 0,

    /**
     * The server is known and has not changed.
     */
    OK,

    /**
     * The server key has changed. Either you are under attack or the
     * administrator changed the key. You HAVE to warn the user about a
     * possible attack.
     */
    CHANGED,

    /**
     * The server gave use a key of a type while we had an other type recorded.
     * It is a possible attack.
     */
    OTHER,
}

MD5_DIGEST_LEN :: 16

Error_Types :: enum c.int {
	NO_ERROR=0,
	REQUEST_DENIED,
	FATAL,
	EINTR
}

/* some types for keys */
Keytypes :: enum c.int {
  UNKNOWN=0,
  DSS=1, /* deprecated */
  RSA,
  RSA1,
  ECDSA, /* deprecated */
  ED25519,
  DSS_CERT01, /* deprecated */
  RSA_CERT01,
  ECDSA_P256,
  ECDSA_P384,
  ECDSA_P521,
  ECDSA_P256_CERT01,
  ECDSA_P384_CERT01,
  ECDSA_P521_CERT01,
  ED25519_CERT01,
  SK_ECDSA,
  SK_ECDSA_CERT01,
  SK_ED25519,
  SK_ED25519_CERT01,
}

Keycmp :: enum c.int {
  PUBLIC = 0,
  PRIVATE = 1,
  CERTIFICATE = 2,
}

ADDRSTRLEN :: 46

Knownhosts_Entry :: struct {
    hostname: [^]u8,
    unparsed: [^]u8,
    publickey: Key,
    comment: [^]u8,
}

/* Error return codes */
OK :: 0     /* No error */
ERROR :: -1 /* Error of some kind */
AGAIN :: -2 /* The nonblocking call must be repeated */
EOF :: -127 /* We have already a eof */


/**
 * @addtogroup libssh_log
 *
 * @{
 */

/** No logging at all
	*/
LOG_NOLOG :: 0
/** Only unrecoverable errors
	*/
LOG_WARNING :: 1
/** Information for the users
	*/
LOG_PROTOCOL :: 2
/** Debug information, to see what is going on
	*/
LOG_PACKET :: 3
/** Trace information and recoverable error messages
	*/
LOG_FUNCTIONS :: 4
/** @} */

LOG_RARE :: LOG_WARNING

/**
 * @name Logging levels
 *
 * @brief Debug levels for logging.
 * @{
 */

/** No logging at all */
LOG_NONE :: 0
/** Show only fatal warnings */
LOG_WARN :: 1
/** Get some information what's going on */
LOG_INFO :: 2
/** Get detailed debugging information **/
LOG_DEBUG :: 3
/** Get trace output, packet information, ... */
LOG_TRACE :: 4

/** @} */

Control_Master_Options :: enum c.int {
  NO,
  AUTO,
  YES,
  ASK,
  AUTOASK
}

Options :: enum c.int {
    HOST,
    PORT,
    PORT_STR,
    FD,
    USER,
    SSH_DIR,
    IDENTITY,
    ADD_IDENTITY,
    KNOWNHOSTS,
    TIMEOUT,
    TIMEOUT_USEC,
    SSH1,
    SSH2,
    LOG_VERBOSITY,
    LOG_VERBOSITY_STR,
    CIPHERS_C_S,
    CIPHERS_S_C,
    COMPRESSION_C_S,
    COMPRESSION_S_C,
    PROXYCOMMAND,
    BINDADDR,
    STRICTHOSTKEYCHECK,
    COMPRESSION,
    COMPRESSION_LEVEL,
    KEY_EXCHANGE,
    HOSTKEYS,
    GSSAPI_SERVER_IDENTITY,
    GSSAPI_CLIENT_IDENTITY,
    GSSAPI_DELEGATE_CREDENTIALS,
    HMAC_C_S,
    HMAC_S_C,
    PASSWORD_AUTH,
    PUBKEY_AUTH,
    KBDINT_AUTH,
    GSSAPI_AUTH,
    GLOBAL_KNOWNHOSTS,
    NODELAY,
    PUBLICKEY_ACCEPTED_TYPES,
    PROCESS_CONFIG,
    REKEY_DATA,
    REKEY_TIME,
    RSA_MIN_SIZE,
    IDENTITY_AGENT,
    IDENTITIES_ONLY,
    CONTROL_MASTER,
    CONTROL_PATH,
    CERTIFICATE,
    PROXYJUMP,
    PROXYJUMP_CB_LIST_APPEND,
}

/** Code is going to write/create remote files */
SCP_WRITE :: 0
/** Code is going to read remote files */
SCP_READ :: 1
SCP_RECURSIVE :: 0x10

Scp_Request_Types :: enum c.int {
  /** A new directory is going to be pulled */
  NEWDIR=1,
  /** A new file is going to be pulled */
  NEWFILE,
  /** End of requests */
  EOF,
  /** End of directory */
  ENDDIR,
  /** Warning received */
  WARNING
}

Connector_Flags :: enum c.int {
    /** Only the standard stream of the channel */
    STDOUT = 1,
    STDINOUT = 1,
    /** Only the exception stream of the channel */
    STDERR = 2,
    /** Merge both standard and exception streams */
    BOTH = 3
}

@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {

    blocking_flush					:: proc(session: Session, timeout: c.int) -> c.int ---
	channel_accept_x11				:: proc(channel: Channel, timeout_ms: c.int) -> Channel ---
	channel_change_pty_size			:: proc(channel: Channel, cols: c.int, rows: c.int) -> c.int ---
	channel_close					:: proc(channel: Channel) -> c.int ---
	channel_free					:: proc(channel: Channel) ---
	channel_get_exit_state			:: proc(channel: Channel, pexit_code: ^c.uint32_t, pexit_signal: ^[^]u8, pcore_dumped: ^c.int) -> c.int ---
	@(deprecated="Please use ssh_channel_exit_state()")
	channel_get_exit_status		    :: proc(channel: Channel) -> c.int ---
	channel_get_session				:: proc(channel: Channel) -> Session ---
	channel_is_closed				:: proc(channel: Channel) -> c.int ---
	channel_is_eof					:: proc(channel: Channel) -> c.int ---
	channel_is_open					:: proc(channel: Channel) -> c.int ---
	channel_new						:: proc(session: Session) -> Channel ---
	channel_open_auth_agent			:: proc(channel: Channel) -> c.int ---
	channel_open_forward			:: proc(channel: Channel, remotehost: cstring, remoteport: c.int, sourcehost: cstring, localport: c.int) -> c.int ---
	channel_open_forward_unix		:: proc(channel: Channel, remotepath: cstring, sourcehost: cstring, localport: c.int) -> c.int ---
	channel_open_session			:: proc(channel: Channel) -> c.int ---
	channel_open_x11				:: proc(channel: Channel, orig_addr: cstring, orig_port: c.int) -> c.int ---
	channel_poll					:: proc(channel: Channel, is_stderr: c.int) -> c.int ---
	channel_poll_timeout			:: proc(channel: Channel, timeout: c.int, is_stderr: c.int) -> c.int ---
	channel_read					:: proc(channel: Channel, dest: rawptr, count: c.uint32_t, is_stderr: c.int) -> c.int ---
	channel_read_timeout			:: proc(channel: Channel, dest: rawptr, count: c.uint32_t, is_stderr: c.int, timeout_ms: c.int) -> c.int ---
	channel_read_nonblocking		:: proc(channel: Channel, dest: rawptr, count: c.uint32_t, is_stderr: c.int) -> c.int ---
    channel_request_env				:: proc(channel: Channel, name: cstring, value: cstring) -> c.int ---
	channel_request_exec			:: proc(channel: Channel, cmd: cstring) -> c.int ---
	channel_request_pty				:: proc(channel: Channel) -> c.int ---
	channel_request_pty_size		:: proc(channel: Channel, term: cstring, cols: c.int, rows: c.int) -> c.int ---
	channel_request_pty_size_modes	:: proc(channel: Channel, term: cstring, cols: c.int, rows: c.int, modes: cstring, modes_len: c.size_t) -> c.int ---
	channel_request_shell			:: proc(channel: Channel) -> c.int ---
	channel_request_send_signal		:: proc(channel: Channel, signum: cstring) -> c.int ---
	channel_request_send_break		:: proc(channel: Channel, length: c.uint32_t) -> c.int ---
	channel_request_sftp			:: proc(channel: Channel) -> c.int ---
	channel_request_subsystem		:: proc(channel: Channel, subsystem: cstring) -> c.int ---

	channel_request_x11			:: proc(channel: Channel, single_connection: c.int, protocol: cstring, cookie: cstring, screen_number: c.int) -> c.int ---
	channel_request_auth_agent	:: proc(channel: Channel) -> c.int ---
	channel_send_eof			:: proc(channel: Channel) -> c.int ---
	channel_set_blocking		:: proc(channel: Channel, blocking: c.int) ---
	channel_set_counter			:: proc(channel: Channel, counter: Counter) ---
	channel_write				:: proc(channel: Channel, data: rawptr, _len: c.uint32_t) -> c.int ---
	channel_write_stderr		:: proc(channel: Channel, data: rawptr, _len: c.uint32_t) -> c.int ---
	channel_window_size			:: proc(channel: Channel) -> c.uint32_t ---

	basename          :: proc(path: cstring) -> cstring ---
	clean_pubkey_hash :: proc(hash: ^[^]u8) ---
	connect           :: proc(session: Session) -> c.int ---

	connector_new             :: proc(session: Session) -> Connector ---
	connector_free            :: proc(connector: Connector) ---
	connector_set_in_channel  :: proc(connector: Connector, channel: Channel, flags: Connector_Flags) -> c.int ---
	connector_set_out_channel :: proc(connector: Connector, channel: Channel, flags: Connector_Flags) -> c.int ---
	connector_set_in_fd       :: proc(connector: Connector, fd: Socket) ---
	connector_set_out_fd      :: proc(connector: Connector, fd: Socket) ---

	copyright  :: proc() -> cstring  ---
	disconnect :: proc(session: Session) ---
	dirname    :: proc(path: cstring) -> cstring ---
	finalize   :: proc() -> c.int ---

	/* REVERSE PORT FORWARDING */
	channel_open_forward_port :: proc(session: Session, timeout_ms: c.int, destination_port: ^c.int, originator: ^[^]u8, originator_port: ^c.int) -> Channel ---
	@(deprecated="deprecate")
	channel_accept_forward    :: proc(session: Session, timeout_ms: c.int, destination_port: ^c.int) -> Channel ---
	channel_cancel_forward    :: proc(session: Session, address: cstring, port: c.int) -> c.int ---
	channel_listen_forward    :: proc(session: Session, address: cstring, port: c.int, bound_port: ^c.int) -> c.int ---

	free                     :: proc(session: Session) ---
	get_disconnect_message   :: proc(session: Session) -> cstring ---
	get_error                :: proc(error: rawptr) -> cstring ---
	get_error_code           :: proc(error: rawptr) -> c.int ---
	get_fd                   :: proc(session: Session) -> Socket ---
	get_hexa                 :: proc(what: cstring, _len: c.size_t) -> ^[^]u8 ---
	get_issue_banner         :: proc(session: Session) -> ^[^]u8 ---
	get_openssh_version      :: proc(session: Session) -> c.int ---
	request_no_more_sessions :: proc(session: Session) -> c.int ---
	get_server_publickey     :: proc(session: Session, key: ^Key) -> c.int ---
}

Publickey_Hash_Type :: enum c.int {
    SHA1,
    MD5,
    SHA256
}

@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {

    get_publickey_hash :: proc(key: Key, type: Publickey_Hash_Type, hash: ^[^]u8, hlen: ^c.size_t ) -> c.int ---

	/* DEPRECATED FUNCTIONS */
    @(deprecated="Use ssh_get_publickey_hash()")
	get_pubkey_hash :: proc(session: Session, hash: ^[^]u8) -> c.int ---
	// forward_accept(Session session, c.int timeout_ms) -> SSH_DEPRECATED Channel ---
	// forward_cancel(Session session, cstring address, c.int port) -> SSH_DEPRECATED c.int ---
	// forward_listen(Session session, cstring address, c.int port, c.int ^bound_port) -> SSH_DEPRECATED c.int ---
	// get_publickey(Session session, ssh_key ^key) -> SSH_DEPRECATED c.int ---
	// write_knownhost(Session session) -> SSH_DEPRECATED c.int ---
	// ^dump_knownhost(Session session) -> SSH_DEPRECATED char ---
	// is_server_known(Session session) -> SSH_DEPRECATED c.int ---
	// print_hexa(cstring descr, const unsigned char ^what, c.size_t len) -> SSH_DEPRECATED void ---
	// channel_select(Channel ^readchans, ssh_channel ^writechans, ssh_channel ^exceptchans, struct timeval * timeout) -> SSH_DEPRECATED c.int ---
	//
	// scp_accept_request(ssh_scp scp) -> SSH_DEPRECATED c.int ---
	// scp_close(ssh_scp scp) -> SSH_DEPRECATED c.int ---
	// scp_deny_request(ssh_scp scp, cstring reason) -> SSH_DEPRECATED c.int ---
	// scp_free(ssh_scp scp) -> SSH_DEPRECATED void ---
	// scp_init(ssh_scp scp) -> SSH_DEPRECATED c.int ---
	// scp_leave_directory(ssh_scp scp) -> SSH_DEPRECATED c.int ---
	// scp_new(Session session, c.int mode, cstring location) -> SSH_DEPRECATED ssh_scp ---
	// scp_pull_request(ssh_scp scp) -> SSH_DEPRECATED c.int ---
	// scp_push_directory(ssh_scp scp, cstring dirname, c.int mode) -> SSH_DEPRECATED c.int ---
	// scp_push_file(ssh_scp scp, cstring filename, c.size_t size, c.int perms) -> SSH_DEPRECATED c.int ---
	// scp_push_file64(ssh_scp scp, cstring filename, uint64_t size, c.int perms) -> SSH_DEPRECATED c.int ---
	// scp_read(ssh_scp scp, void ^buffer, c.size_t size) -> SSH_DEPRECATED c.int ---
	// 	^scp_request_get_filename(ssh_scp scp) -> SSH_DEPRECATED const char ---
	// scp_request_get_permissions(ssh_scp scp) -> SSH_DEPRECATED c.int ---
	// scp_request_get_size(ssh_scp scp) -> SSH_DEPRECATED c.size_t ---
	// scp_request_get_size64(ssh_scp scp) -> SSH_DEPRECATED uint64_t ---
	// 	^scp_request_get_warning(ssh_scp scp) -> SSH_DEPRECATED const char ---
	// scp_write(ssh_scp scp, const void ^buffer, c.size_t len) -> SSH_DEPRECATED c.int ---

	get_random     :: proc(_where: rawptr, _len: c.int , strong: c.int) -> c.int ---
	get_version    :: proc(session: Session) -> c.int ---
	get_status     :: proc(session: Session) -> c.int ---
	get_poll_flags :: proc(session: Session) -> c.int ---
	init           :: proc() -> c.int ---
	is_blocking    :: proc(session: Session) -> c.int ---
	is_connected   :: proc(session: Session) -> c.int ---

	/* KNOWN HOSTS */
	knownhosts_entry_free :: proc(entry: ^Knownhosts_Entry) ---

	known_hosts_parse_line :: proc(host: cstring, line: cstring, entry: ^^Knownhosts_Entry) -> c.int ---

	session_has_known_hosts_entry :: proc(session: Session) -> Known_Hosts ---

	session_export_known_hosts_entry :: proc(session: Session, pentry_string: ^[^]u8) -> c.int ---
	session_update_known_hosts       :: proc(session: Session) -> c.int ---

	session_get_known_hosts_entry :: proc(session: Session, pentry: ^^Knownhosts_Entry) -> Known_Hosts ---
	session_is_known_server       :: proc(session: Session) -> Known_Hosts ---

	/* LOGGING */
	set_log_level    :: proc(level: c.int) -> c.int ---
	get_log_level    :: proc() -> c.int ---
    get_log_userdata :: proc() -> rawptr ---
	set_log_userdata :: proc(data: rawptr) -> c.int ---
    vlog             :: proc (verbosity: c.int, function: cstring, format: cstring, va: ^c.va_list) ---
    @(link_name="_ssh_log")
    _log             :: proc (verbosity: c.int, function: cstring, format: cstring, #c_vararg args: ..any) ---
    @(deprecated="deprecated")
	log              :: proc (session: Session, prioriry: c.int, format: cstring, #c_vararg args: ..any) ---

	message_channel_request_open_reply_accept         :: proc(msg: Message) -> Channel ---
	message_channel_request_open_reply_accept_channel :: proc(msg: Message, chan: Channel) -> c.int ---
	message_channel_request_reply_success             :: proc(msg: Message) -> c.int ---
	message_free                                      :: proc(msg: Message) ---
	message_get                                       :: proc(session: Session) -> Message ---
	message_subtype                                   :: proc(msg: Message) -> c.int ---
	message_type                                      :: proc(msg: Message) -> c.int ---
	mkdir                                             :: proc(pathname: cstring, mode: Mode) -> c.int ---

	// @(link_name="ssh_new")
	new                  :: proc() -> Session ---
	options_copy         :: proc(src: Session, dest: ^Session) -> c.int ---
	options_getopt       :: proc(session: Session, argcptr: ^c.int, argv: ^[^]u8) -> c.int ---
	options_parse_config :: proc(session: Session, filename: cstring) -> c.int ---
	options_set          :: proc(session: Session, type: Options, value: rawptr) -> c.int ---
	options_get          :: proc(session: Session, type: Options, value: ^[^]u8) -> c.int ---
	options_get_port     :: proc(session: Session, port_target: ^c.uint) -> c.int ---
	pcap_file_close      :: proc(pcap: Pcap_File) -> c.int ---
	pcap_file_free       :: proc(pcap: Pcap_File) ---
	pcap_file_new        :: proc() -> Pcap_File ---
	pcap_file_open       :: proc(pcap: Pcap_File, filename: cstring) -> c.int ---
}

CHANNEL_FREE :: #force_inline proc "c" (x: ^Channel) {
	if x^ != nil {
		channel_free(x^)
		x^ = nil
	}
}

KNOWNHOSTS_ENTRY_FREE :: #force_inline proc "c" (x: ^^Knownhosts_Entry) {
	if x^ != nil {
		knownhosts_entry_free(x^)
		x^ = nil
	}
}

MESSAGE_FREE :: #force_inline proc "c" (x: ^Message) {
	if x^ != nil {
		message_free(x^)
		x^ = nil
	}
}


/**
 * @brief SSH authentication callback for password and publickey auth.
 *
 * @param prompt        Prompt to be displayed.
 * @param buf           Buffer to save the password. You should null-terminate it.
 * @param len           Length of the buffer.
 * @param echo          Enable or disable the echo of what you type.
 * @param verify        Should the password be verified?
 * @param userdata      Userdata to be passed to the callback function. Useful
 *                      for GUI applications.
 *
 * @return              0 on success, < 0 on error.
 */
Auth_Callback :: #type proc(prompt: cstring, buf: ^u8, _len: c.size_t, echo: c.int, verify: c.int, userdata: rawptr) -> c.int

File_Format :: enum c.int {
    DEFAULT = 0,
    OPENSSH,
    PEM,
}

@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    key_new            :: proc() -> Key ---
    key_free           :: proc(key: Key) ---
    key_type           :: proc(key: Key) -> Keytypes ---
    key_type_to_char   :: proc(type: Keytypes) -> cstring ---
    key_type_from_name :: proc(name: cstring) -> Keytypes ---
    key_is_public      :: proc(k: Key) -> c.int ---
    key_is_private     :: proc(k: Key) -> c.int ---
    key_cmp            :: proc(k1: Key, k2: Key, what: Keycmp) -> c.int ---
    key_dup            :: proc(key: Key) -> Key ---

    pki_generate                     :: proc(type: Keytypes, parameter: c.int, pkey: ^Key) -> c.int ---
    pki_import_privkey_base64        :: proc(b64_key: cstring, passphrase: cstring, auth_fn: Auth_Callback, auth_data: rawptr, pkey: ^Key) -> c.int ---
    pki_export_privkey_base64        :: proc(privkey: Key, passphrase: cstring, auth_fn: Auth_Callback, auth_data: rawptr, b64_key: ^[^]u8) -> c.int ---
    pki_export_privkey_base64_format :: proc(privkey: Key, passphrase: cstring, auth_fn: Auth_Callback, auth_data: rawptr, b64_key: ^[^]u8, format: File_Format) -> c.int ---
    pki_import_privkey_file          :: proc(filename: cstring, passphrase: cstring, auth_fn: Auth_Callback, auth_data: rawptr, pkey: ^Key) -> c.int ---
    pki_export_privkey_file          :: proc(privkey: Key, passphrase: cstring, auth_fn: Auth_Callback, auth_data: rawptr, filename: cstring) -> c.int ---
    pki_export_privkey_file_format   :: proc(privkey: Key, passphrase: cstring, auth_fn: Auth_Callback, auth_data: rawptr, filename: cstring, format: File_Format) -> c.int ---

    pki_copy_cert_to_privkey :: proc(cert_key: Key, privkey: Key) -> c.int ---

    pki_import_pubkey_base64 :: proc(b64_key : cstring, type: Keytypes, pkey: ^Key) -> c.int ---
    pki_import_pubkey_file   :: proc(filename: cstring, pkey: ^Key) -> c.int ---

    pki_import_cert_base64 :: proc(b64_cert: cstring, type: Keytypes, pkey: ^Key) -> c.int ---
    pki_import_cert_file   :: proc(filename: cstring, pkey: ^Key) -> c.int ---

    pki_export_privkey_to_pubkey :: proc(privkey: Key, pkey    : ^Key) -> c.int ---
    pki_export_pubkey_base64     :: proc(key    : Key, b64_key : ^[^]u8) -> c.int ---
    pki_export_pubkey_file       :: proc(key    : Key, filename: cstring) -> c.int ---

    pki_key_ecdsa_name :: proc(key: Key) -> cstring ---

    get_fingerprint_hash :: proc(type: Publickey_Hash_Type, hash: [^]u8, len: c.size_t) -> [^]u8 ---
    print_hash           :: proc(type: Publickey_Hash_Type, hash: [^]u8, len: c.size_t) ---
    send_ignore          :: proc(session: Session, data: cstring) -> c.int ---
    send_debug           :: proc(session: Session, message: cstring, always_display: c.int) -> c.int ---
    gssapi_set_creds     :: proc(session: Session, creds: Gssapi_Creds) ---
    select               :: proc(channels: ^Channel, outchannels: ^Channel, maxfd: Socket, readfds: ^fd_set, timeout: ^timeval) -> c.int ---
    service_request      :: proc(session: Session, service: cstring) -> c.int ---
    set_agent_channel    :: proc(session: Session, channel: Channel) -> c.int ---
    set_agent_socket     :: proc(session: Session, fd: Socket) -> c.int ---
    set_blocking         :: proc(session: Session, blocking: c.int) ---
    set_counters         :: proc(session: Session, scounter: Counter, rcounter: Counter) ---
    set_fd_except        :: proc(session: Session) ---
    set_fd_toread        :: proc(session: Session) ---
    set_fd_towrite       :: proc(session: Session) ---
    silent_disconnect    :: proc(session: Session) ---
    set_pcap_file        :: proc(session: Session, pcapfile: Pcap_File) -> c.int ---

    /* USERAUTH */
    userauth_none                                :: proc(session: Session, username: cstring) -> c.int ---
    userauth_list                                :: proc(session: Session, username: cstring) -> c.int ---
    userauth_try_publickey                       :: proc(session: Session, username: cstring, pubkey: Key) -> c.int ---
    userauth_publickey                           :: proc(session: Session, username: cstring, privkey: Key) -> c.int ---
    userauth_agent                               :: proc(session: Session, username: cstring) -> c.int ---
    userauth_publickey_auto_get_current_identity :: proc(session: Session, value: ^[^]u8) -> c.int ---
    userauth_publickey_auto                      :: proc(session: Session, username: cstring, passphrase: cstring) -> c.int ---
    userauth_password                            :: proc(session: Session, username: cstring, password: cstring) -> c.int ---

    userauth_kbdint                :: proc(session: Session, user: cstring, submethods: cstring) -> c.int ---
    userauth_kbdint_getinstruction :: proc(session: Session) -> cstring ---
    userauth_kbdint_getname        :: proc(session: Session) -> cstring ---
    userauth_kbdint_getnprompts    :: proc(session: Session) -> c.int ---
    userauth_kbdint_getprompt      :: proc(session: Session, i: c.uint, echo: [^]u8) -> cstring ---
    userauth_kbdint_getnanswers    :: proc(session: Session) -> c.int ---
    userauth_kbdint_getanswer      :: proc(session: Session, i: c.uint) -> cstring ---
    userauth_kbdint_setanswer      :: proc(session: Session, i: c.uint, answer: cstring) -> c.int ---
    userauth_gssapi                :: proc(session: Session) -> c.int ---
    version                        :: proc(req_version: c.int) -> cstring ---

    string_burn      :: proc(str: String) ---
    string_copy      :: proc(str: String) -> String ---
    string_data      :: proc(str: String) -> rawptr ---
    string_fill      :: proc(str: String, data: rawptr, len: c.size_t) -> c.int ---
    string_free      :: proc(str: String) ---
    string_from_char :: proc(what: cstring) -> String ---
    string_len       :: proc(str: String) -> c.size_t ---
    string_new       :: proc(size: c.size_t) -> String ---
    string_get_char  :: proc(str: String) -> cstring ---
    string_to_char   :: proc(str: String) -> ^[^]u8 ---
    string_free_char :: proc(s: ^[^]u8) ---

    getpass :: proc(prompt: cstring, buf: [^]u8, len: c.size_t, echo: c.int, verify: c.int) -> c.int ---
}

Event_Callback :: #type proc(fd: Socket, revents: c.int, userdata: rawptr) -> c.int

@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    event_new              :: proc() -> Event ---
    event_add_fd           :: proc(event: Event, fd: Socket, events: c.short, cb: Event_Callback, userdata: rawptr) -> c.int ---
    event_add_session      :: proc(event: Event, session: Session) -> c.int ---
    event_add_connector    :: proc(event: Event, connector: Connector) -> c.int ---
    event_dopoll           :: proc(event: Event, timeout: c.int) -> c.int ---
    event_remove_fd        :: proc(event: Event, fd: Socket) -> c.int ---
    event_remove_session   :: proc(event: Event, session: Session) -> c.int ---
    event_remove_connector :: proc(event: Event, connector: Connector) -> c.int ---
    event_free             :: proc(event: Event) ---

    get_clientbanner   :: proc(session: Session) -> cstring ---
    get_serverbanner   :: proc(session: Session) -> cstring ---
    get_kex_algo       :: proc(session: Session) -> cstring ---
    get_cipher_in      :: proc(session: Session) -> cstring ---
    get_cipher_out     :: proc(session: Session) -> cstring ---
    get_hmac_in        :: proc(session: Session) -> cstring ---
    get_hmac_out       :: proc(session: Session) -> cstring ---

    buffer_new :: proc() -> Buffer ---
    buffer_free :: proc(buffer: Buffer) ---
    buffer_reinit :: proc(buffer: Buffer) -> c.int ---
    buffer_add_data :: proc(buffer: Buffer, data: rawptr, len: c.uint32_t) -> c.int ---
    buffer_get_data :: proc(buffer: Buffer, data: rawptr, requestedlen: c.uint32_t) -> c.uint32_t ---
    buffer_get :: proc(buffer: Buffer) -> rawptr ---
    buffer_get_len :: proc(buffer: Buffer) -> c.uint32_t ---
    session_set_disconnect_message :: proc(session: Session, message: cstring) -> c.int ---
}

KEY_FREE :: #force_inline proc "c" (x: ^Key) {
    if x^ != nil {
        key_free(x^)
        x^ = nil
    }
}

STRING_FREE :: #force_inline proc "c" (x: ^String) {
    if x^ != nil {
        string_free(x^)
        x^ = nil
    }
}

STRING_FREE_CHAR :: #force_inline proc "c" (x: ^^[^]u8) {
    if x^ != nil {
        string_free_char(x^)
        x^ = nil
    }
}

BUFFER_FREE :: #force_inline proc "c" (x: ^Buffer) {
    if x^ != nil {
        buffer_free(x^)
        x^ = nil
    }
}
