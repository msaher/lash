local buffer = require("string.buffer")
local SshCmd = lash._get_metatable("SshCmd").__index

--- @class lash.ssh.ExitState
--- @field exit_code? number
--- @field exit_signal? string
--- @field stderr? string

--- @param opts { password: string }
function ssh.AuthPassword(opts)
    return {
        type = "password",
        password = opts.password,
    }
end

--- @param opts { passphrase: string? }
function ssh.AuthPublickey(opts)
    return {
        type = "publickey",
        passphrase = opts.passphrase
    }
end

--- @param opts { publickey: string, privatekey: string, passphrase: string?}
function ssh.AuthPublickeyFile(opts)
    return {
        type = "publickey_file",
        publickey = opts.publickey,
        privatekey = opts.privatekey,
        passphrase = opts.passphrase,
    }
end

--- @param opts {}
local function AuthAgent()
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
