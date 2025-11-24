local M = {}

local uv = lash.uv
local buffer = require("string.buffer")

-- TODO: consider a cmd:must_run()

M.SIGHUP    = 'sighup'
M.SIGINT    = 'sigint'
M.SIGQUIT   = 'sigquit'
M.SIGILL    = 'sigill'
M.SIGTRAP   = 'sigtrap'
M.SIGABRT   = 'sigabrt'
M.SIGIOT    = 'sigiot'
M.SIGBUS    = 'sigbus'
M.SIGFPE    = 'sigfpe'
M.SIGKILL   = 'sigkill'
M.SIGUSR1   = 'sigusr1'
M.SIGSEGV   = 'sigsegv'
M.SIGUSR2   = 'sigusr2'
M.SIGPIPE   = 'sigpipe'
M.SIGALRM   = 'sigalrm'
M.SIGTERM   = 'sigterm'
M.SIGCHLD   = 'sigchld'
M.SIGSTKFLT = 'sigstkflt'
M.SIGCONT   = 'sigcont'
M.SIGSTOP   = 'sigstop'
M.SIGTSTP   = 'sigtstp'
M.SIGBREAK  = 'sigbreak'
M.SIGTTIN   = 'sigttin'
M.SIGTTOU   = 'sigttou'
M.SIGURG    = 'sigurg'
M.SIGXCPU   = 'sigxcpu'
M.SIGXFSZ   = 'sigxfsz'
M.SIGVTALRM = 'sigvtalrm'
M.SIGPROF   = 'sigprof'
M.SIGWINCH  = 'sigwinch'
M.SIGIO     = 'sigio'
M.SIGPOLL   = 'sigpoll'
M.SIGLOST   = 'siglost'
M.SIGPWR    = 'sigpwr'
M.SIGSYS    = 'sigsys'


--- @class lash.proc.CmdOpts
--- @field args string
--- @field cwd? string
--- @field env? string[]
--- @field stdout? uv.uv_stream_t
--- @field stdin? uv.uv_stream_t
--- @field stderr? uv.uv_stream_t
--- @field detach? boolean

--- @class lash.proc.Cmd : lash.proc.CmdOpts
--- @field process? lash.proc.Process
--- @field process_state? lash.proc.ProcessState
local Cmd = {}

--- @param opts lash.proc.CmdOpts
function M.Cmd(opts)
    return setmetatable(opts, {
        __index = Cmd,
    })
end

--- @class lash.proc.Process
--- @field handle uv.uv_process_t
--- @field pid number
--- @field state? lash.proc.ProcessState
local Process = {}

--- @class lash.proc.ProcessState
--- @field code number
--- @field signal number
local ProcessState = {}

--- @class lash.proc.ExitErr
--- @field state lash.proc.ProcessState
--- @field stderr string

--- @return boolean
function ProcessState:success()
    -- TODO: is this right?
    return self.code == 0
end

--- @param signal string | number
--- @return number
function Process:kill(signal)
    return uv.process_kill(self.handle, signal)
end

--- @return ProcessState
function Process:wait()
    while self.handle and self.handle:is_active() do
        uv.run("once")
    end
    return self.state
end

--- @return Process
function Cmd:start()
    -- TODO: what if it fails?
    local process_state = setmetatable({}, { __index = ProcessState })
    local process = setmetatable({ state = process_state }, { __index = Process })
    local handle, pid = uv.spawn(self.args[1], { args = lash.list_slice(self.args, 2),
        stdio = {self.stdin, self.stdout, self.stderr},
        cwd = self.cwd,
        env = self.env,
        detached = self.detach,
        on_exit = function(code, signal)
            print("on exit")
            process_state.code = code
            process_state.signal = signal
        end
    })
    process.handle = handle
    process.pid = pid
    self.process = process

    return process
end

--- @return lash.proc.ProcessState
function Cmd:run()
    local process = self:start()
    return process:wait()
end

--- Calls process:wait() on the underlying process
--- @return lash.proc.ProcessState
function Cmd:wait()
    assert(self.process ~= nil, "Cannot wait on cmd when there's no process")
    return self.process:wait()
end

--- @param cmd Cmd
--- @param stdout_r uv.uv_pipe_t
--- @param stderr_r uv.uv_pipe_t
--- @param stdout_b buffer
--- @param stderr_b buffer
local function _output(cmd, stdout_b, stderr_b)
    assert(cmd.stdout == nil, "Cannot redirect stdout when it's being captured")
    assert(cmd.stderr == nil, "Cannot redirect stdout when it's being captured")

    cmd.stdout = uv.new_pipe()
    cmd.stderr = uv.new_pipe()

    local process = cmd:start()

    uv.read_start(cmd.stdout, function(err, data)
        assert(not err, err)
        -- if no data means end
        if data then
            stdout_b:put(data)
        end
    end)

    uv.read_start(cmd.stderr, function(err, data)
        assert(not err, err)
        -- if no data means end
        if data then
            stderr_b:put(data)
        end
    end)

    local state = process:wait()
    local err = nil
    if not state:success() then
        err = { state = state }
        if stderr_b ~= stdout_b then
            err.stderr = stderr_b:tostring()
        end
    end

    return stdout_b:tostring(), err
end


--- @return (string, lash.proc.ExitErr?)
function Cmd:output()
    local stdout_b = buffer.new()
    local stderr_b = buffer.new()
    return _output(self, stdout_b, stderr_b)
end

--- @return (string, lash.proc.ExitErr?)
function Cmd:combined_output()
    local buf = buffer.new()
    return _output(self, buf, buf)
end

--- Runs command through $SHELL -c
--- If shell is unset default to `sh`
--- @param args string
--- @param ... any
--- @return lash.proc.Cmd
function M.sh(args, ...)
    local shell = os.getenv("SHELL") or "sh"
    local args = table.concat({args, ...}, " ")

    return M.Cmd {
        args = {shell, "-c", args},
    }
end

return M
