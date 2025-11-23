package luv

import lua "../luajit"
import "core:c"

foreign import luv "../vendor-luv/build/libluv.a"

@(link_prefix="lua")
@(default_calling_convention="c")
foreign luv {
    open_luv :: proc(L: ^lua.State) -> c.int ---
}
