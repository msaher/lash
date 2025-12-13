local buffer = require("string.buffer")
local SshCmd = lash._get_metatable("SshCmd").__index

M = {}

--- @class Session

--- @class SessionCmd
--- @field session Session
--- @field args string[]
--- @field stdout buffer?
--- @field stderr buffer?
--- @field stdin string?
--- @field pty bool?

--- @class ConnectOpts
--- @field host string
--- @field user string
--- @field port number?
--- @field auth AuthMethod

--- @class ExitState
--- @field exit_code? number
--- @field exit_signal? string
--- @field stderr? string

--- @param opts { password: string }
--- @return AuthMethod
function M.AuthPassword(opts)
    return {
        type = "password",
        password = opts.password,
    }
end

--- @param opts { passphrase: string? }
--- @return AuthMethod
function M.AuthPublickey(opts)
    return {
        type = "publickey",
        passphrase = opts.passphrase
    }
end

--- @param opts { publickey: string, privatekey: string, passphrase: string?}
--- @return AuthMethod
function M.AuthPublickeyFile(opts)
    return {
        type = "publickey_file",
        publickey = opts.publickey,
        privatekey = opts.privatekey,
        passphrase = opts.passphrase,
    }
end

--- @param opts {}
--- @return AuthMethod
function M.AuthAgent()
    return {
        type = "agent",
    }
end

--- @return (string, lash.ssh.ExitState)
function SshCmd:output()
    assert(self.stdout == nil, "Cannot redirect stdout when it's being captured")
    self.stdout = buffer.new()

    -- TODO: consider using a prefix suffix buffer in case a it writes a lot to stderr
    local capture_err = self.stderr == nil
    if capture_err then
        self.stderr = buffer.new()
    end

    local exit_state = self:run()
    return self.stdout:tostring(), exit_state
end

--- @return (string, lash.ssh.ExitState)
function SshCmd:combined_output()
    assert(self.stdout == nil, "Cannot redirect stdout when it's being captured")
    assert(self.stderr == nil, "Cannot redirect stderr when it's being captured")
    local buf = buffer.new()
    self.stdout = buf
    self.stderr = buf

    local exit_state = self:run()
    return self.stdout:tostring(), exit_state
end

--- @param opts ConnectOpts
--- @return Session
function M.connect(opts)
    return lash._ssh_connect(opts)
end

return M
