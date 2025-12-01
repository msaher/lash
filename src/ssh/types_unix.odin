#+build linux, darwin, freebsd, openbsd, netbsd, haiku
package ssh

import "core:c"
import "core:sys/posix"

Socket :: c.int
fd_set :: posix.fd_set
timeval :: posix.timeval
