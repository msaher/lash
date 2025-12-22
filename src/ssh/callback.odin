package ssh

import "core:c"

foreign import ssh {
    "../libssh-0.11.3/build/src/libssh.a",
    "system:ssl",
    "system:crypto",
    "system:gssapi_krb5",
    "system:z",
}

/**
 * @defgroup libssh_callbacks The libssh callbacks
 * @ingroup libssh
 *
 * Callback which can be replaced in libssh.
 *
 * @{
 */

/** @internal
 * @brief callback to process simple codes
 * @param code value to transmit
 * @param user Userdata to pass in callback
 */
Callback_Int :: proc "c" (code: c.int, user: rawptr)

/** @internal
 * @brief callback for data received messages.
 * @param data data retrieved from the socket or stream
 * @param len number of bytes available from this stream
 * @param user user-supplied pointer sent along with all callback messages
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
Callback_Data :: proc "c" (data: rawptr, len: c.size_t, user: rawptr) -> c.size_t

Callback_Int_Int :: proc "c" (code: c.int, errno_code: c.int, user: rawptr)

Message_Callback :: proc "c" (channel: Channel, message: Message, user: rawptr) -> c.int
Channel_Callback_Int :: proc "c" (channel: Channel, code: c.int, user: rawptr) -> c.int
Channel_Callback_Data :: proc "c" (channel: Channel, code: c.int, data: rawptr, len: c.size_t, user: rawptr) -> c.int

/**
 * @brief SSH log callback. All logging messages will go through this callback
 * @param session Current session handler
 * @param priority Priority of the log, the smaller being the more important
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
Log_Callback :: proc "c" (session: Session, priority: c.int, message: cstring, userdata: rawptr)

/**
 * @brief SSH log callback.
 *
 * All logging messages will go through this callback.
 *
 * @param priority  Priority of the log, the smaller being the more important.
 *
 * @param function  The function name calling the logging functions.
 *
 * @param buffer   The actual message
 *
 * @param userdata Userdata to be passed to the callback function.
 */
Logging_Callback :: proc "c" (priority: c.int, function: cstring, buffer: cstring, userdata: rawptr)

/**
 * @brief SSH Connection status callback.
 * @param session Current session handler
 * @param status Percentage of connection status, going from 0.0 to 1.0
 * once connection is done.
 * @param userdata Userdata to be passed to the callback function.
 */
Status_Callback :: proc "c" (session: Session, status: c.float, userdata: rawptr)

/**
 * @brief SSH global request callback. All global request will go through this
 * callback.
 * @param session Current session handler
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
Global_Request_Callback :: proc "c" (session: Session, message: Message, userdata: rawptr)


/**
 * @brief Handles an SSH new channel open X11 request. This happens when the server
 * sends back an X11 connection attempt. This is a client-side API
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @param originator_address    IP address of the machine who sent the request
 * @param originator_port   port number of the machine who sent the request
 * @returns a valid Session handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
Channel_Open_Request_X11_Callback :: proc "c" (session: Session, originator_address: cstring , originator_port: c.int, userdata: rawptr) -> Session

/**
 * @brief Handles an SSH new channel open "auth-agent" request. This happens when the server
 * sends back an "auth-agent" connection attempt. This is a client-side API
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid Session handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
Channel_Open_Request_Auth_Agent_Callback :: proc "c" (session: Session, userdata: rawptr) -> Session

/**
 * @brief Handles an SSH new channel open "forwarded-tcpip" request. This
 * happens when the server forwards an incoming TCP connection on a port it was
 * previously requested to listen on. This is a client-side API
 * @param session current session handler
 * @param destination_address the address that the TCP connection connected to
 * @param destination_port the port that the TCP connection connected to
 * @param originator_address the originator IP address
 * @param originator_port the originator port
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid Session handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the
 * application.
 */
Channel_Open_Request_Forwarded_Tcpip_Callback :: proc "c" (session: Session, destination_address: cstring, destination_port: c.int, originator_address: cstring, originator_port: c.int, userdata: rawptr) -> Session

/**
 * The structure to replace libssh functions with appropriate callbacks.
 */
Callbacks_Struct :: struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
    size: c.size_t,
  /**
   * User-provided data. User is free to set anything he wants here
   */
  userdata: rawptr,
  /**
   * This functions will be called if e.g. a keyphrase is needed.
   */
  auth_function: Auth_Callback,
  /**
   * This function will be called each time a loggable event happens.
   */
  log_function: Log_Callback,
  /**
   * This function gets called during connection time to indicate the
   * percentage of connection steps completed.
   */
  connect_status_function: proc "c" (userdata: rawptr, status: c.float),
  /**
   * This function will be called each time a global request is received.
   */
    global_request_function: Global_Request_Callback,
  /** This function will be called when an incoming X11 request is received.
   */
  channel_open_request_x11_function: Channel_Open_Request_X11_Callback,
  /** This function will be called when an incoming "auth-agent" request is received.
   */
  channel_open_request_auth_agent_function: Channel_Open_Request_Auth_Agent_Callback,
  /**
   * This function will be called when an incoming "forwarded-tcpip"
   * request is received.
   */
  channel_open_request_forwarded_tcpip_function: Channel_Open_Request_Forwarded_Tcpip_Callback,
}

Callbacks :: ^Callbacks_Struct;


/**
 * @brief SSH authentication callback.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param password Password used for authentication
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
Auth_Password_Callback :: proc "c" (session: Session, user: cstring, password: cstring, userdata: rawptr) -> c.int

/**
 * @brief SSH authentication callback. Tries to authenticates user with the "none" method
 * which is anonymous or passwordless.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
Auth_None_Callback :: proc "c" (session: Session, user: cstring, userdata: rawptr) -> c.int

/**
 * @brief SSH authentication callback. Tries to authenticates user with the "gssapi-with-mic" method
 * @param session Current session handler
 * @param user Username of the user (can be spoofed)
 * @param principal Authenticated principal of the user, including realm.
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 * @warning Implementations should verify that parameter user matches in some way the principal.
 * user and principal can be different. Only the latter is guaranteed to be safe.
 */
Auth_Gssapi_Mic_Callback :: proc "c" (session: Session, user: cstring, principal: cstring, userdata: rawptr) -> c.int


/**
 * @brief SSH authentication callback.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param pubkey public key used for authentication
 * @param signature_state SSH_PUBLICKEY_STATE_NONE if the key is not signed (simple public key probe),
 *							SSH_PUBLICKEY_STATE_VALID if the signature is valid. Others values should be
 *							replied with a SSH_AUTH_DENIED.
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
Auth_Pubkey_Callback :: proc "c" (session: Session, user: cstring, pubkey: Key, signature_state: byte, userdata: rawptr)



/**
 * @brief Handles an SSH service request
 * @param session current session handler
 * @param service name of the service (e.g. "ssh-userauth") requested
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the request is to be allowed
 * @returns -1 if the request should not be allowed
 */

Service_Request_Callback :: proc "c" (session: Session, service: cstring, userdata: rawptr) -> c.int

/**
 * @brief Handles an SSH new channel open session request
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid Session handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
Channel_Open_Request_Session_Callback :: proc "c" (session: Session, userdata: rawptr) -> Session

/*
 * @brief handle the beginning of a GSSAPI authentication, server side.
 *        Callback should select the oid and also acquire the server credential.
 * @param session current session handler
 * @param user the username of the client
 * @param n_oid number of available oids
 * @param oids OIDs provided by the client
 * @returns an ssh_string containing the chosen OID, that's supported by both
 * client and server.
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
Gssapi_Select_Oid_Callback :: proc "c" (session: Session, user: cstring, n_oid: c.int, oids: ^String, userdata: rawptr) -> String

/*
 * @brief handle the negotiation of a security context, server side.
 * @param session current session handler
 * @param[in] input_token input token provided by client
 * @param[out] output_token output of the gssapi accept_sec_context method,
 *				NULL after completion.
 * @returns SSH_OK if the token was generated correctly or accept_sec_context
 * returned GSS_S_COMPLETE
 * @returns SSH_ERROR in case of error
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
Gssapi_Accept_Sec_Ctx_Callback :: proc "c" (session: Session, input_token: String, output_token: ^String, userdata: rawptr) -> c.int

/*
 * @brief Verify and authenticates a MIC, server side.
 * @param session current session handler
 * @param[in] mic input mic to be verified provided by client
 * @param[in] mic_buffer buffer of data to be signed.
 * @param[in] mic_buffer_size size of mic_buffer
 * @returns SSH_OK if the MIC was authenticated correctly
 * @returns SSH_ERROR in case of error
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
Gssapi_Verify_Mic_Callback :: proc "c" (session: Session, mic: String, mic_buffer: rawptr, mic_buffer_size: c.size_t, userdata: rawptr) -> c.int


/**
 * This structure can be used to implement a libssh server, with appropriate callbacks.
 */

Server_Callbacks_Struct :: struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
    size: c.size_t,
  /**
   * User-provided data. User is free to set anything he wants here
   */
  userdata: rawptr,
  /** This function gets called when a client tries to authenticate through
   * password method.
   */
  auth_password_function: Auth_Password_Callback,

  /** This function gets called when a client tries to authenticate through
   * none method.
   */
  auth_none_function: Auth_None_Callback,

  /** This function gets called when a client tries to authenticate through
   * gssapi-mic method.
   */
  auth_gssapi_mic_function: Auth_Gssapi_Mic_Callback,

  /** this function gets called when a client tries to authenticate or offer
   * a public key.
   */
  auth_pubkey_function: Auth_Pubkey_Callback,

  /** This functions gets called when a service request is issued by the
   * client
   */
  service_request_function: Service_Request_Callback,
  /** This functions gets called when a new channel request is issued by
   * the client
   */
  channel_open_request_session_function: Channel_Open_Request_Session_Callback,
  /** This function will be called when a new gssapi authentication is attempted.
   * This should select the oid and acquire credential for the server.
   */
  gssapi_select_oid_function: Gssapi_Select_Oid_Callback,
  /** This function will be called when a gssapi token comes in.
   */
  gssapi_accept_sec_ctx_function: Gssapi_Accept_Sec_Ctx_Callback,
  /* This function will be called when a MIC needs to be verified.
   */
  gssapi_verify_mic_function: Gssapi_Verify_Mic_Callback,
}

Server_Callbacks :: ^Server_Callbacks_Struct

/**
 * @brief Set the session server callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for user authentication, new channels and requests.
 *
 * Note, that the structure is not copied to the session structure so it needs
 * to be valid for the whole session lifetime.
 *
 * @code
 * struct ssh_server_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_password_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_server_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    set_server_callbacks :: proc (session: Session, cb: Server_Callbacks) -> c.int ---
}

/**
 * These are the callbacks exported by the socket structure
 * They are called by the socket module when a socket event appears
 */
Socket_Callbacks_Struct :: struct {
  /**
   * User-provided data. User is free to set anything he wants here
   */
    userdata: rawptr,
	/**
	 * This function will be called each time data appears on socket. The data
	 * not consumed will appear on the next data event.
	 */
  data: Callback_Data,
  /** This function will be called each time a controlflow state changes, i.e.
   * the socket is available for reading or writing.
   */
  controlflow: Callback_Int,
  /** This function will be called each time an exception appears on socket. An
   * exception can be a socket problem (timeout, ...) or an end-of-file.
   */
  exception: Callback_Int_Int,
  /** This function is called when the ssh_socket_connect was used on the socket
   * on nonblocking state, and the connection succeeded.
   */
  connected: Callback_Int_Int,
}

Socket_Callbacks :: ^Socket_Callbacks_Struct

SOCKET_FLOW_WRITEWILLBLOCK :: 1
SOCKET_FLOW_WRITEWONTBLOCK :: 2

SOCKET_EXCEPTION_EOF       :: 1
SOCKET_EXCEPTION_ERROR     :: 2

SOCKET_CONNECTED_OK        :: 1
SOCKET_CONNECTED_ERROR     :: 2
SOCKET_CONNECTED_TIMEOUT   :: 3

callbacks_init_callbacks :: proc "c" (p: Callbacks) {
    p.size = size_of(p^)
}

callbacks_init_channel_callbacks :: proc "c" (p: Channel_Callbacks) {
    p.size = size_of(p^)
}

/**
 * @brief Initializes an ssh_callbacks_struct
 * A call to this macro is mandatory when you have set a new
 * ssh_callback_struct structure. Its goal is to maintain the binary
 * compatibility with future versions of libssh as the structure
 * evolves with time.
 */
callbacks_init :: proc{callbacks_init_callbacks, callbacks_init_channel_callbacks}


/** @brief Prototype for a packet callback, to be called when a new packet arrives
 * @param session The current session of the packet
 * @param type packet type (see ssh2.h)
 * @param packet buffer containing the packet, excluding size, type and padding fields
 * @param user user argument to the callback
 * and are called each time a packet shows up
 * @returns SSH_PACKET_USED Packet was parsed and used
 * @returns SSH_PACKET_NOT_USED Packet was not used or understood, processing must continue
 */
Packet_Callback :: proc "c" (session: Session, type: c.uint8_t, packet: Buffer, user: rawptr) -> c.int

/** return values for a ssh_packet_callback */
/** Packet was used and should not be parsed by another callback */
PACKET_USED :: 1
/** Packet was not used and should be passed to any other callback
 * available */
PACKET_NOT_USED :: 2


/** @brief This macro declares a packet callback handler
 * @code
 * SSH_PACKET_CALLBACK(mycallback){
 * ...
 * }
 * @endcode
 */
// #define SSH_PACKET_CALLBACK(name) \
// 	c.int name (Session session, c.uint8_t type, ssh_buffer packet, rawptr user)

Packet_Callbacks_Struct :: struct {
    /** Index of the first packet type being handled */
    start: c.uint8_t,
    /** Number of packets being handled by this callback struct */
    n_callbacks: c.uint8_t,
    /** A pointer to n_callbacks packet callbacks */
    callbacks: Packet_Callback,
    /**
     * User-provided data. User is free to set anything he wants here
     */
    user: rawptr,
}

Packet_Callbacks :: ^Packet_Callbacks_Struct;

/**
 * @brief Set the session callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for auth, logging and status.
 *
 * Note, that the callback structure is not copied into the session so it needs
 * to be valid for the whole session lifetime.
 *
 * @code
 * struct ssh_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    ssh_set_callbacks :: proc (session: Session, cb: Callbacks) -> c.int ---
}

/**
 * @brief SSH channel data callback. Called when data is available on a channel
 * @param session Current session handler
 * @param channel the actual channel
 * @param data the data that has been read on the channel
 * @param len the length of the data
 * @param is_stderr is 0 for stdout or 1 for stderr
 * @param userdata Userdata to be passed to the callback function.
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
Channel_Data_Callback :: proc "c" (session: Session, channel: Channel, data: rawptr, len: c.uint32_t, is_stderr: b32, userdata: rawptr) -> c.int

/**
 * @brief SSH channel eof callback. Called when a channel receives EOF
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Eof_Callback :: proc "c" (session: Session, channel: Channel, userdata: rawptr)

/**
 * @brief SSH channel close callback. Called when a channel is closed by remote peer
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Close_Callback :: proc "c" (session: Session, channel: Channel, userdata: rawptr)

/**
 * @brief SSH channel signal callback. Called when a channel has received a signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Signal_Callback :: proc "c" (session: Session, channel: Channel, signal: cstring, userdata: rawptr)

/**
 * @brief SSH channel exit status callback. Called when a channel has received an exit status
 * @param session Current session handler
 * @param channel the actual channel
 * @param exit_status Exit status of the ran command
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Exit_Status_Callback :: proc "c" (session: Session, channel: Channel, exit_status: c.int, userdata: rawptr)

/**
 * @brief SSH channel exit signal callback. Called when a channel has received an exit signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param core a boolean telling whether a core has been dumped or not
 * @param errmsg the description of the exception
 * @param lang the language of the description (format: RFC 3066)
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Exit_Signal_Callback :: proc "c" (session: Session, channel: Channel, signal: cstring, core: c.int, errmsg: cstring, lang: cstring, userdata: rawptr)

/**
 * @brief SSH channel PTY request from a client.
 * @param session the session
 * @param channel the channel
 * @param term The type of terminal emulation
 * @param width width of the terminal, in characters
 * @param height height of the terminal, in characters
 * @param pxwidth width of the terminal, in pixels
 * @param pwheight height of the terminal, in pixels
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the pty request is accepted
 * @returns -1 if the request is denied
 */
Channel_Pty_Request_Callback :: proc "c" (session: Session, channel: Channel, term: cstring, width: c.int, height: c.int, pxwidth: c.int, pwheight: c.int, userdata: rawptr) -> c.int

/**
 * @brief SSH channel Shell request from a client.
 * @param session the session
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the shell request is accepted
 * @returns 1 if the request is denied
 */
Channel_Shell_Request_Callback :: proc "c" (session: Session, channel: Channel, userdata: rawptr) -> c.int

/**
 * @brief SSH auth-agent-request from the client. This request is
 * sent by a client when agent forwarding is available.
 * Server is free to ignore this callback, no answer is expected.
 * @param session the session
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Auth_Agent_Req_Callback :: proc "c" (session: Session, channel: Channel, userdata: rawptr)

/**
 * @brief SSH X11 request from the client. This request is
 * sent by a client when X11 forwarding is requested(and available).
 * Server is free to ignore this callback, no answer is expected.
 * @param session the session
 * @param channel the channel
 * @param single_connection If true, only one channel should be forwarded
 * @param auth_protocol The X11 authentication method to be used
 * @param auth_cookie   Authentication cookie encoded hexadecimal
 * @param screen_number Screen number
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_X11_Req_Callback :: proc "c" (session: Session, channel: Channel, single_connection: c.int, auth_protocol: cstring, auth_cookie: cstring, screen_number: c.uint32_t, userdata: rawptr)
/**
 * @brief SSH channel PTY windows change (terminal size) from a client.
 * @param session the session
 * @param channel the channel
 * @param width width of the terminal, in characters
 * @param height height of the terminal, in characters
 * @param pxwidth width of the terminal, in pixels
 * @param pwheight height of the terminal, in pixels
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the pty request is accepted
 * @returns -1 if the request is denied
 */
Channel_Pty_Window_Change_Callback :: proc "c" (session: Session, channel: Channel, width: c.int, height: c.int, pxwidth: c.int, pwheight: c.int, userdata: rawptr) -> c.int
/**
 * @brief SSH channel Exec request from a client.
 * @param session the session
 * @param channel the channel
 * @param command the shell command to be executed
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the exec request is accepted
 * @returns 1 if the request is denied
 */
Channel_Exec_Request_Callback :: proc "c" (session: Session, channel: Channel, command: cstring, userdata: rawptr) -> c.int

/**
 * @brief SSH channel environment request from a client.
 * @param session the session
 * @param channel the channel
 * @param env_name name of the environment value to be set
 * @param env_value value of the environment value to be set
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the env request is accepted
 * @returns 1 if the request is denied
 * @warning some environment variables can be dangerous if changed (e.g.
 * 			LD_PRELOAD) and should not be fulfilled.
 */
Channel_Env_Request_Callback :: proc "c" (session: Session, channel: Channel, env_name: cstring, env_value: cstring, userdata: rawptr) -> c.int

/**
 * @brief SSH channel subsystem request from a client.
 * @param session the session
 * @param channel the channel
 * @param subsystem the subsystem required
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the subsystem request is accepted
 * @returns 1 if the request is denied
 */
Channel_Subsystem_Request_Callback :: proc "c" (session: Session, channel: Channel, subsystem: cstring, userdata: rawptr) -> c.int

/**
 * @brief SSH channel write will not block (flow control).
 *
 * @param session the session
 *
 * @param channel the channel
 *
 * @param[in] bytes size of the remote window in bytes. Writing as much data
 *            will not block.
 *
 * @param[in] userdata Userdata to be passed to the callback function.
 *
 * @returns 0 default return value (other return codes may be added in future).
 */
Channel_Write_Wontblock_Callback :: proc "c" (session: Session, channel: Channel, bytes: c.uint32_t, userdata: rawptr) -> c.int

/**
 * @brief SSH channel open callback. Called when a channel open succeeds or fails.
 * @param session Current session handler
 * @param channel the actual channel
 * @param is_success is 1 when the open succeeds, and 0 otherwise.
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Open_Resp_Callback :: proc "c" (session: Session, channel: Channel, is_success: bool, userdata: rawptr)

/**
 * @brief SSH channel request response callback. Called when a response to the pending request is received.
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
Channel_Request_Resp_Callback :: proc "c" (session: Session, channel: Channel, userdata: rawptr)

Channel_Callbacks_Struct :: struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
    size: c.size_t,
  /**
   * User-provided data. User is free to set anything he wants here
   */
  userdata: rawptr,
  /**
   * This functions will be called when there is data available.
   */
  channel_data_function: Channel_Data_Callback,
  /**
   * This functions will be called when the channel has received an EOF.
   */
  channel_eof_function: Channel_Eof_Callback,
  /**
   * This functions will be called when the channel has been closed by remote
   */
  channel_close_function: Channel_Close_Callback,
  /**
   * This functions will be called when a signal has been received
   */
  channel_signal_function: Channel_Signal_Callback,
  /**
   * This functions will be called when an exit status has been received
   */
  channel_exit_status_function: Channel_Exit_Status_Callback,
  /**
   * This functions will be called when an exit signal has been received
   */
  channel_exit_signal_function: Channel_Exit_Signal_Callback,
  /**
   * This function will be called when a client requests a PTY
   */
  channel_pty_request_function: Channel_Pty_Request_Callback,
  /**
   * This function will be called when a client requests a shell
   */
  channel_shell_request_function: Channel_Shell_Request_Callback,
  /** This function will be called when a client requests agent
   * authentication forwarding.
   */
  channel_auth_agent_req_function: Channel_Auth_Agent_Req_Callback,
  /** This function will be called when a client requests X11
   * forwarding.
   */
  channel_x11_req_function: Channel_X11_Req_Callback,
  /** This function will be called when a client requests a
   * window change.
   */
  channel_pty_window_change_function: Channel_Pty_Window_Change_Callback,
  /** This function will be called when a client requests a
   * command execution.
   */
  channel_exec_request_function: Channel_Exec_Request_Callback,
  /** This function will be called when a client requests an environment
   * variable to be set.
   */
  channel_env_request_function: Channel_Env_Request_Callback,
  /** This function will be called when a client requests a subsystem
   * (like sftp).
   */
  channel_subsystem_request_function: Channel_Subsystem_Request_Callback,
  /** This function will be called when the channel write is guaranteed
   * not to block.
   */
  channel_write_wontblock_function: Channel_Write_Wontblock_Callback,
  /**
   * This functions will be called when the channel has received a channel open confirmation or failure.
   */
  channel_open_response_function: Channel_Open_Resp_Callback,
  /**
   * This functions will be called when the channel has received the response to the pending request.
   */
  channel_request_response_function: Channel_Request_Resp_Callback,
};

Channel_Callbacks :: ^Channel_Callbacks_Struct

/**
 * @brief Set the channel callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for channel data and exceptions.
 *
 * Note, that the structure is not copied to the channel structure so it needs
 * to be valid as for the whole life of the channel or until it is removed with
 * ssh_remove_channel_callbacks().
 *
 * @codE
 * struct Session_callbacks_struct cb = {
 *   .userdata = data,
 *   .channel_data_function = my_channel_data_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_channel_callbacks(channel, &cb);
 * @endcode
 *
 * @param  channel      The channel to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 * @warning this function will not replace existing callbacks but set the
 *          new one atop of them.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    set_channel_callbacks :: proc (channel: Channel, cb: Channel_Callbacks) -> c.int ---
}

/**
 * @brief Add channel callback functions
 *
 * This function will add channel callback functions to the channel callback
 * list.
 * Callbacks missing from a callback structure will be probed in the next
 * on the list.
 *
 * @param  channel      The channel to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_set_channel_callbacks
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    add_channel_callbacks :: proc (channel: Channel, cb: Channel_Callbacks) -> c.int ---
}

/**
 * @brief Remove a channel callback.
 *
 * The channel has been added with ssh_add_channel_callbacks or
 * ssh_set_channel_callbacks in this case.
 *
 * @param channel  The channel to remove the callback structure from.
 *
 * @param cb       The callback structure to remove
 *
 * @returns SSH_OK on success, SSH_ERROR on error.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    remove_channel_callbacks :: proc (channel: Channel, cb: Channel_Callbacks) -> c.int ---
}

/** @} */

/** @addtogroup libssh_threads
 * @{
 */

Thread_Callback :: proc "c" (lock: rawptr) -> c.int

Thread_Id_Callback :: proc "c" () -> c.ulong

Threads_Callbacks_Struct :: struct {
    type: cstring,
    mutex_init   : Thread_Callback,
    mutex_destroy: Thread_Callback,
    mutex_lock   : Thread_Callback,
    mutex_unlock : Thread_Callback,
    thread_id    : Thread_Id_Callback,
};

/**
 * @brief Set the thread callbacks structure.
 *
 * This is necessary if your program is using libssh in a multithreaded fashion.
 * This function must be called first, outside of any threading context (in your
 * main() function for instance), before you call ssh_init().
 *
 * @param[in] cb   A pointer to a ssh_threads_callbacks_struct structure, which
 *                 contains the different callbacks to be set.
 *
 * @returns        Always returns SSH_OK.
 *
 * @see ssh_threads_callbacks_struct
 * @see SSH_THREADS_PTHREAD
 * @bug libgcrypt 1.6 and bigger backend does not support custom callback.
 *      Using anything else than pthreads here will fail.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    threads_set_callbacks :: proc (cb: ^Threads_Callbacks_Struct) -> c.int ---
}

/**
 * @brief Returns a pointer to the appropriate callbacks structure for the
 * environment, to be used with ssh_threads_set_callbacks.
 *
 * @returns A pointer to a ssh_threads_callbacks_struct to be used with
 * ssh_threads_set_callbacks.
 *
 * @see ssh_threads_set_callbacks
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    threads_get_default :: proc() -> ^Threads_Callbacks_Struct ---
}

/**
 * @brief Returns a pointer on the pthread threads callbacks, to be used with
 * ssh_threads_set_callbacks.
 *
 * @see ssh_threads_set_callbacks
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    threads_get_pthread :: proc() -> ^Threads_Callbacks_Struct ---
}

/**
 * @brief Get the noop threads callbacks structure
 *
 * This can be used with ssh_threads_set_callbacks. These callbacks do nothing
 * and are being used by default.
 *
 * @return Always returns a valid pointer to the noop callbacks structure.
 *
 * @see ssh_threads_set_callbacks
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    threads_get_noop :: proc() -> ^Threads_Callbacks_Struct ---
}
/** @} */

/**
 * @brief Set the logging callback function.
 *
 * @param[in]  cb  The callback to set.
 *
 * @return         0 on success, < 0 on error.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    set_log_callback :: proc(cb: Logging_Callback) -> c.int ---
}

/**
 * @brief Get the pointer to the logging callback function.
 *
 * @return The pointer the the callback or NULL if none set.
 */
@(link_prefix="ssh_")
@(default_calling_convention="c")
foreign ssh {
    get_log_callback :: proc() -> Logging_Callback ---
}

/**
 * @brief SSH proxyjump before connection callback. Called before calling
 * ssh_connect()
 * @param session Jump session handler
 * @param userdata Userdata to be passed to the callback function.
 *
 * @return         0 on success, < 0 on error.
 */
Jump_Before_Connection_Callback :: proc "c" (session: Session, userdata: rawptr) -> c.int

/**
 * @brief SSH proxyjump verify knownhost callback. Verify the host.
 *        If not specified default function will be used.
 * @param session Jump session handler
 * @param userdata Userdata to be passed to the callback function.
 *
 * @return         0 on success, < 0 on error.
 */
Jump_Verify_Knownhost_Callback :: proc "c" (session: Session, userdata: rawptr) -> c.int

/**
 * @brief SSH proxyjump user authentication callback. Authenticate the user.
 * @param session Jump session handler
 * @param userdata Userdata to be passed to the callback function.
 *
 * @return         0 on success, < 0 on error.
 */
Jump_Authenticate_Callback :: proc "c" (session: Session, userdata: rawptr) -> c.int

Jump_Callbacks_Struct :: struct {
    userdata: rawptr,
    before_connection: Jump_Before_Connection_Callback,
    verify_knownhost: Jump_Verify_Knownhost_Callback,
    authenticate: Jump_Authenticate_Callback,
}
