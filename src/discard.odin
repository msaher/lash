package main

import "core:io"

discard_proc :: proc (stream_data: rawptr, mode: io.Stream_Mode, p: []byte, offset: i64, whence: io.Seek_From) -> (i64, io.Error) {
    #partial switch mode {
    case .Query:
        return io.query_utility({.Read, .Write})
    case .Read: fallthrough
    case .Write:
        return i64(len(p)), .None
    case:
        return 0, .Empty
    }
}

discard_stream :: io.Stream {
    procedure = discard_proc
}

