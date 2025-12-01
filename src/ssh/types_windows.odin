#+build windows
package ssh

import "core:sys/windows"

Socket :: sys_windows.SOCKET
fd_set :: sys_windows.fd_set
timeval :: sys_windows.timeval
