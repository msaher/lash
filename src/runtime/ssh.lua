local buffer = require("string.buffer")
local SshCmd = lash._get_metatable("SshCmd").__index

--- @class lash.ssh.ExitState
--- @field exit_code? number
--- @field exit_signal? string
--- @field stderr? string

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
