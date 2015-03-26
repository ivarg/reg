# reg
reg is a crude, simple, and incomplete Go API to the Windows registry. It tries
to wrap existing `syscall` registry functions in a Go idiomatic way, as well as
extend them with direct syscalls to the Windows API functions to allow setting.

