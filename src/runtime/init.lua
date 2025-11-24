-- initialized once lash runs
-- lots of functions taken from neovim's stdlib
-- TODO: add license if needed

lash.inspect = require("inspect")
lash.proc = require("proc")

local function _print(inspect_strings, ...)
  local msg = {}
  for i = 1, select('#', ...) do
    local o = select(i, ...)
    if not inspect_strings and type(o) == 'string' then
      table.insert(msg, o)
    else
      table.insert(msg, lash.inspect(o, { newline = '\n', indent = '  ' }))
    end
  end
  print(table.concat(msg, '\n'))
  return ...
end

-- from neovim
--- @param ... any
--- @return any # given arguments.
function lash.print(...)
  return _print(false, ...)
end

-- from neovim
--- Creates a copy of a table containing only elements from start to end (inclusive)
---
---@generic T
---@param list T[] Table
---@param start integer|nil Start range of slice
---@param finish integer|nil End range of slice
---@return T[] Copy of table sliced from start to finish (inclusive)
function lash.list_slice(list, start, finish)
  local new_list = {} --- @type `T`[]
  for i = start or 1, finish or #list do
    new_list[#new_list + 1] = list[i]
  end
  return new_list
end
